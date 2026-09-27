import http from "node:http";
import dns from "node:dns/promises";
import { URL } from "node:url";
import httpProxy from "http-proxy";

const PORT = Number(process.env.PORT || 3000);
const ALLOWED_HOSTS = ["*"];

function isAllowed(hostname) {
    if (ALLOWED_HOSTS.includes("*")) return true;

    hostname = hostname.toLowerCase();

    return ALLOWED_HOSTS.some(host =>
        hostname === host ||
        hostname.endsWith("." + host)
    );
}

const proxy = httpProxy.createProxyServer({
    changeOrigin: true,
    xfwd: true,
    ws: true,
    secure: false,
    selfHandleResponse: true
});

async function validateTarget(target) {
    if (
        !["http:", "https:"].includes(
            target.protocol
        )
    ) {
        throw new Error(
            "Only HTTP/HTTPS URLs are allowed."
        );
    }

    if (!isAllowed(target.hostname)) {
        throw new Error(
            `Host not allowed: ${target.hostname}.`
        );
    }

    const results =
        await dns.lookup(
            target.hostname,
            {
                all: true
            }
        );

    for (const entry of results) {

        const ip =
            entry.address;

        if (
            ip === "127.0.0.1" ||
            ip === "::1" ||
            ip.startsWith("10.") ||
            ip.startsWith("192.168.") ||
            ip.startsWith("169.254.") ||
            (
                ip.startsWith("172.") &&
                parseInt(
                    ip.split(".")[1]
                ) >= 16 &&
                parseInt(
                    ip.split(".")[1]
                ) <= 31
            )
        ) {
            throw new Error(
                "Private/local targets are blocked."
            );
        }
    }
}

function relayURL(url) {
    return (
        "/relay?url=" +
        encodeURIComponent(url)
    );
}

function rewriteURL(value, base) {

    if (!value) {
        return value;
    }

    const trimmed =
        String(value).trim();

    if (
        trimmed.startsWith("#") ||
        trimmed.startsWith("javascript:") ||
        trimmed.startsWith("mailto:") ||
        trimmed.startsWith("tel:") ||
        trimmed.startsWith("data:") ||
        trimmed.startsWith("blob:")
    ) {
        return value;
    }

    try {

        const absolute =
            new URL(
                trimmed,
                base
            );

        if (
            absolute.protocol === "http:" ||
            absolute.protocol === "https:"
        ) {

            return relayURL(
                absolute.href
            );

        }

        return value;

    } catch {

        return value;

    }
}

function rewriteHTML(body, baseURL) {

    let html = body;

    /*
     * Remove existing <base> tags.
     *
     * We resolve URLs ourselves against the
     * real target URL.
     */

    html =
        html.replace(
            /<base\b[^>]*>/gi,
            ""
        );


    /*
     * Remove target-site policies that would prevent
     * the relay from modifying/embedding the document.
     */

    html =
        html.replace(
            /<meta\s+[^>]*http-equiv\s*=\s*["']?(Content-Security-Policy|X-Frame-Options)["']?[^>]*>/gi,
            ""
        );


    /*
     * Remove target-site referrer policy tags.
     * The response header below supplies our own
     * same-origin policy.
     */

    html =
        html.replace(
            /<meta\s+[^>]*http-equiv\s*=\s*["']?Referrer-Policy["']?[^>]*>/gi,
            ""
        );


    /*
     * Remove SRI integrity attributes because the
     * relay modifies resources and can otherwise
     * invalidate their hashes.
     */

    html =
        html.replace(
            /\bintegrity\s*=\s*(["']).*?\1/gi,
            ""
        );


    /*
     * Rewrite normal URL-bearing attributes.
     */

    html =
        html.replace(
            /\b(href|src|action|poster|formaction|data|cite)\s*=\s*(["'])(.*?)\2/gi,
            (
                full,
                attr,
                quote,
                value
            ) => {

                const rewritten =
                    rewriteURL(
                        value,
                        baseURL
                    );

                return (
                    attr +
                    "=" +
                    quote +
                    rewritten +
                    quote
                );

            }
        );


    /*
     * Rewrite CSS url(...)
     */

    html =
        html.replace(
            /url\(\s*(["']?)(.*?)\1\s*\)/gi,
            (
                full,
                quote,
                value
            ) => {

                const rewritten =
                    rewriteURL(
                        value,
                        baseURL
                    );

                return (
                    "url(" +
                    quote +
                    rewritten +
                    quote +
                    ")"
                );

            }
        );


    /*
     * Rewrite srcset entries.
     */

    html =
        html.replace(
            /\bsrcset\s*=\s*(["'])(.*?)\1/gi,
            (
                full,
                quote,
                value
            ) => {

                const rewritten =
                    value
                        .split(",")
                        .map(part => {

                            const pieces =
                                part
                                    .trim()
                                    .split(/\s+/);

                            if (
                                !pieces.length
                            ) {
                                return part;
                            }

                            pieces[0] =
                                rewriteURL(
                                    pieces[0],
                                    baseURL
                                );

                            return pieces.join(
                                " "
                            );

                        })
                        .join(", ");

                return (
                    "srcset=" +
                    quote +
                    rewritten +
                    quote
                );

            }
        );


    /*
     * =================================================
     * EARLY RELAY SCRIPT
     * =================================================
     *
     * IMPORTANT:
     *
     * This script is inserted at the START of <head>.
     * That means YouTube's JavaScript sees our patched
     * fetch/XHR/history APIs when its own scripts load.
     *
     * This is what fixes requests such as:
     *
     * suggestqueries-clients6.youtube.com
     */

    const injected = `
<script>
(() => {

    const TARGET_BASE =
        ${JSON.stringify(baseURL)};

    const RELAY_ORIGIN =
        location.origin;

    const relay =
        ${JSON.stringify(relayURL)};


    /*
     * =================================================
     * URL CONVERSION
     * =================================================
     */

    function proxyURL(raw) {

        try {

            if (raw == null) {
                return raw;
            }

            const value =
                String(raw);

            if (
                value.startsWith("data:") ||
                value.startsWith("blob:") ||
                value.startsWith("javascript:") ||
                value.startsWith("mailto:") ||
                value.startsWith("tel:") ||
                value.startsWith("#")
            ) {
                return value;
            }


            /*
             * If the URL is already a relay URL,
             * don't relay it again.
             */

            let current = null;

            try {

                current =
                    new URL(
                        value,
                        location.href
                    );

            } catch {}


            if (
                current &&
                current.origin ===
                    RELAY_ORIGIN &&
                current.pathname ===
                    "/relay"
            ) {

                return current.href;

            }


            /*
             * Resolve against the REAL target,
             * not the relay server.
             */

            let absolute =
                new URL(
                    value,
                    TARGET_BASE
                );


            /*
             * If a site somehow constructed a URL
             * against the relay origin, convert that
             * path back into the original target.
             */

            if (
                current &&
                current.origin ===
                    RELAY_ORIGIN
            ) {

                absolute =
                    new URL(
                        current.pathname +
                        current.search +
                        current.hash,
                        TARGET_BASE
                    );

            }


            if (
                absolute.protocol !==
                    "http:" &&
                absolute.protocol !==
                    "https:"
            ) {

                return value;

            }


            /*
             * EVERYTHING external becomes same-origin
             * /relay?url=...
             */

            return relay(
                absolute.href
            );

        } catch {

            return raw;

        }

    }


    /*
     * =================================================
     * FETCH
     * =================================================
     */

    const originalFetch =
        window.fetch;

    window.fetch =
        function(input, init) {

            try {

                if (
                    typeof input ===
                        "string" ||
                    input instanceof URL
                ) {

                    input =
                        proxyURL(
                            input
                        );

                } else if (
                    input instanceof Request
                ) {

                    const proxied =
                        proxyURL(
                            input.url
                        );

                    input =
                        new Request(
                            proxied,
                            input
                        );

                }

            } catch {}

            return originalFetch.call(
                this,
                input,
                init
            );

        };


    /*
     * =================================================
     * XHR
     * =================================================
     */

    const originalOpen =
        XMLHttpRequest.prototype.open;

    XMLHttpRequest.prototype.open =
        function(
            method,
            url,
            ...rest
        ) {

            try {

                url =
                    proxyURL(url);

            } catch {}

            return originalOpen.call(
                this,
                method,
                url,
                ...rest
            );

        };


    /*
     * =================================================
     * WEBSOCKET
     * =================================================
     */

    const NativeWebSocket =
        window.WebSocket;

    function proxyWS(raw) {

        try {

            const value =
                String(raw);

            let absolute =
                new URL(
                    value,
                    TARGET_BASE
                );

            let current = null;

            try {

                current =
                    new URL(
                        value,
                        location.href
                    );

            } catch {}


            if (
                current &&
                current.origin ===
                    RELAY_ORIGIN &&
                current.pathname !==
                    "/relay"
            ) {

                absolute =
                    new URL(
                        current.pathname +
                        current.search +
                        current.hash,
                        TARGET_BASE
                    );

            }


            if (
                absolute.protocol ===
                    "ws:" ||
                absolute.protocol ===
                    "wss:"
            ) {

                return relay(
                    absolute.href
                )
                .replace(
                    /^http:/,
                    "ws:"
                )
                .replace(
                    /^https:/,
                    "wss:"
                );

            }

            return value;

        } catch {

            return raw;

        }

    }

    window.WebSocket =
        function(
            url,
            protocols
        ) {

            const proxied =
                proxyWS(url);

            if (
                protocols ===
                    undefined
            ) {

                return new NativeWebSocket(
                    proxied
                );

            }

            return new NativeWebSocket(
                proxied,
                protocols
            );

        };

    window.WebSocket.prototype =
        NativeWebSocket.prototype;

    window.WebSocket.CONNECTING =
        NativeWebSocket.CONNECTING;

    window.WebSocket.OPEN =
        NativeWebSocket.OPEN;

    window.WebSocket.CLOSING =
        NativeWebSocket.CLOSING;

    window.WebSocket.CLOSED =
        NativeWebSocket.CLOSED;


    /*
     * =================================================
     * EVENTSOURCE
     * =================================================
     */

    if (window.EventSource) {

        const NativeEventSource =
            window.EventSource;

        window.EventSource =
            function(
                url,
                options
            ) {

                return new NativeEventSource(
                    proxyURL(url),
                    options
                );

            };

        window.EventSource.prototype =
            NativeEventSource.prototype;

        window.EventSource.CONNECTING =
            NativeEventSource.CONNECTING;

        window.EventSource.OPEN =
            NativeEventSource.OPEN;

        window.EventSource.CLOSED =
            NativeEventSource.CLOSED;

    }


    /*
     * =================================================
     * SEND BEACON
     * =================================================
     */

    if (navigator.sendBeacon) {

        const originalBeacon =
            navigator.sendBeacon.bind(
                navigator
            );

        navigator.sendBeacon =
            function(
                url,
                data
            ) {

                return originalBeacon(
                    proxyURL(url),
                    data
                );

            };

    }


    /*
     * =================================================
     * WINDOW.OPEN
     * =================================================
     */

    const originalWindowOpen =
        window.open;

    window.open =
        function(
            url,
            ...args
        ) {

            if (
                url == null ||
                url === ""
            ) {

                return originalWindowOpen.call(
                    this,
                    url,
                    ...args
                );

            }

            return originalWindowOpen.call(
                this,
                proxyURL(url),
                ...args
            );

        };


    /*
     * =================================================
     * HISTORY API
     * =================================================
     *
     * YouTube uses history.pushState /
     * history.replaceState extensively for SPA
     * navigation.
     */

    const originalPushState =
        history.pushState;

    history.pushState =
        function(
            state,
            title,
            url
        ) {

            if (
                url != null
            ) {

                url =
                    proxyURL(url);

            }

            return originalPushState.call(
                this,
                state,
                title,
                url
            );

        };


    const originalReplaceState =
        history.replaceState;

    history.replaceState =
        function(
            state,
            title,
            url
        ) {

            if (
                url != null
            ) {

                url =
                    proxyURL(url);

            }

            return originalReplaceState.call(
                this,
                state,
                title,
                url
            );

        };


    /*
     * =================================================
     * LINKS
     * =================================================
     */

    document.addEventListener(
        "click",
        event => {

            const link =
                event.target.closest?.(
                    "a[href]"
                );

            if (!link) {
                return;
            }

            if (
                event.defaultPrevented
            ) {
                return;
            }

            try {

                const raw =
                    link.getAttribute(
                        "href"
                    );

                const absolute =
                    new URL(
                        raw,
                        TARGET_BASE
                    );

                if (
                    absolute.protocol ===
                        "http:" ||
                    absolute.protocol ===
                        "https:"
                ) {

                    event.preventDefault();

                    location.href =
                        proxyURL(
                            absolute.href
                        );

                }

            } catch {}

        },
        true
    );


    /*
     * =================================================
     * FORMS
     * =================================================
     */

    document.addEventListener(
        "submit",
        event => {

            const form =
                event.target.closest?.(
                    "form"
                );

            if (!form) {
                return;
            }

            try {

                const action =
                    form.getAttribute(
                        "action"
                    ) ||
                    location.href;

                form.setAttribute(
                    "action",
                    proxyURL(action)
                );

            } catch {}

        },
        true
    );


    /*
     * =================================================
     * FORM SUBMIT()
     * =================================================
     */

    const originalFormSubmit =
        HTMLFormElement.prototype.submit;

    HTMLFormElement.prototype.submit =
        function() {

            try {

                const action =
                    this.getAttribute(
                        "action"
                    ) ||
                    location.href;

                this.setAttribute(
                    "action",
                    proxyURL(action)
                );

            } catch {}

            return originalFormSubmit.call(
                this
            );

        };


})();
</script>`;


    /*
     * =================================================
     * INSERT EARLY
     * =================================================
     */

    if (
        /<head\b[^>]*>/i.test(
            html
        )
    ) {

        html =
            html.replace(
                /(<head\b[^>]*>)/i,
                "$1" +
                injected
            );

    } else {

        html =
            injected +
            html;

    }

    return html;
}


/*
 * =====================================================
 * OUTBOUND REQUEST HEADERS
 * =====================================================
 */

proxy.on(
    "proxyReq",
    (proxyReq, req) => {

        /*
         * Ask the destination for uncompressed data
         * because HTML must be modified before returning it.
         */

        proxyReq.setHeader(
            "accept-encoding",
            "identity"
        );


        /*
         * Browser-like headers.
         */

        proxyReq.setHeader(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        );


        /*
         * Don't force an HTML Accept header over APIs.
         * Preserve the browser's value when available.
         */

        if (
            !req.headers.accept
        ) {

            proxyReq.setHeader(
                "accept",
                "*/*"
            );

        } else {

            proxyReq.setHeader(
                "accept",
                req.headers.accept
            );

        }

        proxyReq.setHeader(
            "accept-language",
            req.headers[
                "accept-language"
            ] ||
            "en-US,en;q=0.9"
        );


        const target =
            req._relayTarget;

        if (target) {

            proxyReq.setHeader(
                "host",
                target.host
            );


            /*
             * The destination sees its own origin,
             * not the relay origin.
             */

            if (
                req.headers.origin
            ) {

                proxyReq.setHeader(
                    "origin",
                    target.origin
                );

            }


            /*
             * Send a sensible destination referer.
             */

            if (
                req.headers.referer
            ) {

                proxyReq.setHeader(
                    "referer",
                    target.origin + "/"
                );

            }

        }

    }
);


/*
 * =====================================================
 * INBOUND PROXY RESPONSE
 * =====================================================
 */

proxy.on(
    "proxyRes",
    async (
        proxyRes,
        req,
        res
    ) => {

        const target =
            req._relayTarget;


        /*
         * Remove headers that can prevent embedding,
         * rewriting, or subsequent same-origin requests.
         */

        delete proxyRes.headers[
            "x-frame-options"
        ];

        delete proxyRes.headers[
            "content-security-policy"
        ];

        delete proxyRes.headers[
            "content-security-policy-report-only"
        ];

        delete proxyRes.headers[
            "cross-origin-opener-policy"
        ];

        delete proxyRes.headers[
            "cross-origin-embedder-policy"
        ];

        delete proxyRes.headers[
            "cross-origin-resource-policy"
        ];

        delete proxyRes.headers[
            "strict-transport-security"
        ];

        delete proxyRes.headers[
            "report-to"
        ];

        delete proxyRes.headers[
            "nel"
        ];

        delete proxyRes.headers[
            "clear-site-data"
        ];


        /*
         * Make same-origin continuation requests carry
         * the full relay URL in Referer.
         */

        proxyRes.headers[
            "referrer-policy"
        ] = "same-origin";


        /*
         * Rewrite cookies so they belong to the relay
         * rather than the destination host.
         */

        if (
            proxyRes.headers[
                "set-cookie"
            ]
        ) {

            proxyRes.headers[
                "set-cookie"
            ] =
                proxyRes.headers[
                    "set-cookie"
                ].map(cookie =>
                    cookie
                        .replace(
                            /;\s*Domain=[^;]*/gi,
                            ""
                        )
                        .replace(
                            /;\s*SameSite=None/gi,
                            "; SameSite=Lax"
                        )
                );

        }


        /*
         * IMPORTANT:
         *
         * Redirects from the target must stay inside
         * the relay.
         */

        if (
            proxyRes.headers.location
        ) {

            try {

                const location =
                    new URL(
                        proxyRes.headers.location,
                        target.href
                    );

                proxyRes.headers.location =
                    relayURL(
                        location.href
                    );

            } catch {}

        }


        const contentType =
            proxyRes.headers[
                "content-type"
            ] || "";

        const chunks = [];


        proxyRes.on(
            "data",
            chunk => {
                chunks.push(chunk);
            }
        );


        proxyRes.on(
            "end",
            () => {

                let body =
                    Buffer.concat(
                        chunks
                    );


                /*
                 * HTML gets rewritten so its links,
                 * scripts, images, forms, APIs, etc.
                 * stay inside the relay.
                 */

                if (
                    contentType.includes(
                        "text/html"
                    )
                ) {

                    body =
                        Buffer.from(
                            rewriteHTML(
                                body.toString(
                                    "utf8"
                                ),
                                target.href
                            ),
                            "utf8"
                        );

                    proxyRes.headers[
                        "content-length"
                    ] =
                        String(
                            body.length
                        );

                }


                delete proxyRes.headers[
                    "transfer-encoding"
                ];


                res.writeHead(
                    proxyRes.statusCode ||
                        200,
                    proxyRes.statusMessage,
                    proxyRes.headers
                );

                res.end(
                    body
                );

            }
        );

    }
);


/*
 * =====================================================
 * PROXY ERROR
 * =====================================================
 */

proxy.on(
    "error",
    (
        err,
        req,
        res
    ) => {

        console.error(
            "Proxy error:",
            err.message
        );

        if (
            res &&
            !res.headersSent
        ) {

            res.writeHead(
                502,
                {
                    "content-type":
                        "text/plain; charset=utf-8"
                }
            );

        }

        if (res) {

            res.end(
                "Relay error: " +
                err.message
            );

        }

    }
);


/*
 * =====================================================
 * GET TARGET
 * =====================================================
 *
 * Supports:
 *
 *   /relay?url=https://example.com/page
 *
 * AND:
 *
 *   /results?search_query=test
 *
 * when the latter is a continuation of a relayed
 * page.
 */

function getTarget(req) {

    const requestURL =
        new URL(
            req.url,
            `http://${req.headers.host}`
        );


    /*
     * Explicit relay URL.
     */

    const raw =
        requestURL.searchParams.get(
            "url"
        );

    if (raw) {

        return new URL(
            raw
        );

    }


    /*
     * Relay continuation.
     *
     * The mirrored document is hosted at the relay
     * origin, so a navigation to:
     *
     *     /results?search_query=test
     *
     * needs to be mapped back to:
     *
     *     https://target-site/results?search_query=test
     */

    const referer =
        req.headers.referer;

    if (!referer) {

        throw new Error(
            "Missing relay target."
        );

    }

    const refererURL =
        new URL(
            referer
        );


    /*
     * Only accept relay continuations from our own
     * /relay endpoint.
     */

    if (
        refererURL.pathname !==
            "/relay"
    ) {

        throw new Error(
            "Not a relay continuation."
        );

    }


    const relayTarget =
        refererURL.searchParams.get(
            "url"
        );

    if (!relayTarget) {

        throw new Error(
            "Relay target missing from referrer."
        );

    }


    const targetBase =
        new URL(
            relayTarget
        );


    return new URL(
        requestURL.pathname +
        requestURL.search,
        targetBase.origin
    );

}


/*
 * =====================================================
 * SERVER
 * =====================================================
 */

const server =
    http.createServer(
        async (
            req,
            res
        ) => {

            /*
             * =================================================
             * CORS
             * =================================================
             */

            res.setHeader(
                "Access-Control-Allow-Origin",
                req.headers.origin ||
                    "*"
            );

            res.setHeader(
                "Access-Control-Allow-Methods",
                "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS"
            );

            res.setHeader(
                "Access-Control-Allow-Headers",
                req.headers[
                    "access-control-request-headers"
                ] ||
                    "*"
            );

            res.setHeader(
                "Access-Control-Allow-Credentials",
                "true"
            );

            res.setHeader(
                "Vary",
                "Origin"
            );


            /*
             * =================================================
             * HEALTH
             * =================================================
             */

            if (
                req.url ===
                    "/health"
            ) {

                res.writeHead(
                    200,
                    {
                        "content-type":
                            "application/json"
                    }
                );

                res.end(
                    JSON.stringify({
                        ok: true,
                        allowedHosts:
                            ALLOWED_HOSTS
                    })
                );

                return;

            }


            /*
             * =================================================
             * PREFLIGHT
             * =================================================
             *
             * The browser may issue OPTIONS before a
             * relay request. Handle it at OUR server so
             * the destination's CORS policy isn't involved.
             */

            if (
                req.method ===
                    "OPTIONS"
            ) {

                try {

                    const target =
                        getTarget(req);

                    await validateTarget(
                        target
                    );

                    res.writeHead(
                        204
                    );

                    res.end();

                } catch {

                    res.writeHead(
                        204
                    );

                    res.end();

                }

                return;

            }


            /*
             * =================================================
             * EXPLICIT RELAY
             * =================================================
             */

            if (
                req.url.startsWith(
                    "/relay"
                )
            ) {

                try {

                    const target =
                        getTarget(req);

                    await validateTarget(
                        target
                    );

                    req._relayTarget =
                        target;


                    /*
                     * Only the destination path/query is
                     * passed to http-proxy.
                     */

                    req.url =
                        target.pathname +
                        target.search;


                    proxy.web(
                        req,
                        res,
                        {
                            target:
                                target.origin
                        }
                    );

                } catch (err) {

                    res.writeHead(
                        403,
                        {
                            "content-type":
                                "text/plain; charset=utf-8"
                        }
                    );

                    res.end(
                        err.message
                    );

                }

                return;

            }


            /*
             * =================================================
             * RELAY CONTINUATION
             * =================================================
             *
             * This is the part that fixes:
             *
             * /results
             * /watch
             * /shorts/...
             * /login
             * /search
             * /whatever
             *
             * being mistaken for backend endpoints.
             */

            try {

                const target =
                    getTarget(req);

                await validateTarget(
                    target
                );

                req._relayTarget =
                    target;

                req.url =
                    target.pathname +
                    target.search;

                proxy.web(
                    req,
                    res,
                    {
                        target:
                            target.origin
                    }
                );

            } catch {

                res.writeHead(
                    404,
                    {
                        "content-type":
                            "text/plain; charset=utf-8"
                    }
                );

                res.end(
                    "Not found"
                );

            }

        }
    );


server.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `Relay: http://localhost:${PORT}`
        );

    }
);
