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
        hostname === host || hostname.endsWith("." + host)
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
    if (!["http:", "https:"].includes(target.protocol)) {
        throw new Error("Only HTTP/HTTPS URLs are allowed.");
    }

    if (!isAllowed(target.hostname)) {
        throw new Error(`Host not allowed: ${target.hostname}.`);
    }

    const results = await dns.lookup(target.hostname, { all: true });
    for (const entry of results) {
        const ip = entry.address;
        if (
            ip === "127.0.0.1" || ip === "::1" || ip.startsWith("10.") ||
            ip.startsWith("192.168.") || ip.startsWith("169.254.") ||
            (ip.startsWith("172.") && parseInt(ip.split('.')[1]) >= 16 && parseInt(ip.split('.')[1]) <= 31)
        ) {
            throw new Error("Private/local targets are blocked.");
        }
    }
}

function relayURL(url) {
    return "/relay?url=" + encodeURIComponent(url);
}

function rewriteURL(value, base) {
    if (!value) return value;
    const trimmed = value.trim();

    if (
        trimmed.startsWith("#") || trimmed.startsWith("javascript:") ||
        trimmed.startsWith("mailto:") || trimmed.startsWith("tel:") ||
        trimmed.startsWith("data:")
    ) {
        return value;
    }

    try {
        const absolute = new URL(trimmed, base);
        if (absolute.protocol === "http:" || absolute.protocol === "https:") {
            return relayURL(absolute.href);
        }
        return value;
    } catch {
        return value;
    }
}

function rewriteHTML(body, baseURL) {
    let html = body;

    // Remove existing base tags
    html = html.replace(/<base\b[^>]*>/gi, "");

    // Remove security meta tags
    html = html.replace(/<meta\s+[^>]*http-equiv\s*=\s*["']?(Content-Security-Policy|X-Frame-Options)["']?[^>]*>/gi, "");

    // FIX: Remove SRI (integrity) attributes so modified scripts aren't blocked by the browser
    html = html.replace(/\bintegrity\s*=\s*(["']).*?\1/gi, "");

    // Rewrite common URL-bearing attributes
    html = html.replace(
        /\b(href|src|action|poster|formaction|data|cite)\s*=\s*(["'])(.*?)\2/gi,
        (full, attr, quote, value) => {
            const rewritten = rewriteURL(value, baseURL);
            return `${attr}=${quote}${rewritten}${quote}`;
        }
    );

    // Rewrite CSS url(...)
    html = html.replace(
        /url\(\s*(["']?)(.*?)\1\s*\)/gi,
        (full, quote, value) => {
            const rewritten = rewriteURL(value, baseURL);
            return `url(${quote}${rewritten}${quote})`;
        }
    );

    // Rewrite srcset entries
    html = html.replace(
        /\bsrcset\s*=\s*(["'])(.*?)\1/gi,
        (full, quote, value) => {
            const rewritten = value.split(",").map(part => {
                const pieces = part.trim().split(/\s+/);
                if (!pieces.length) return part;
                pieces[0] = rewriteURL(pieces[0], baseURL);
                return pieces.join(" ");
            }).join(", ");
            return `srcset=${quote}${rewritten}${quote}`;
        }
    );

    const injected = `
<script>
(() => {
    const TARGET_BASE = ${JSON.stringify(baseURL)};
    const relay = ${JSON.stringify(relayURL)};

    function proxyURL(raw) {
        try {
            if (raw == null) return raw;

            const value = String(raw);

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

            const absolute = new URL(value, TARGET_BASE);

            if (
                absolute.protocol === "http:" ||
                absolute.protocol === "https:"
            ) {
                return relay(encodeURIComponent(absolute.href));
            }

            return value;
        } catch {
            return raw;
        }
    }

    function proxyWS(raw) {
        try {
            const absolute = new URL(raw, TARGET_BASE);

            if (
                absolute.protocol === "ws:" ||
                absolute.protocol === "wss:"
            ) {
                return relay(
                    encodeURIComponent(
                        absolute.href
                    )
                ).replace(/^http:/, "ws:")
                 .replace(/^https:/, "wss:");
            }

            return raw;
        } catch {
            return raw;
        }
    }

    // fetch()
    const originalFetch = window.fetch;

    window.fetch = function(input, init) {
        try {
            if (typeof input === "string" ||
                input instanceof URL) {

                input = proxyURL(input);

            } else if (input instanceof Request) {

                const proxied = proxyURL(input.url);

                input = new Request(
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

    // XMLHttpRequest
    const originalOpen =
        XMLHttpRequest.prototype.open;

    XMLHttpRequest.prototype.open =
        function(method, url, ...rest) {

            try {
                url = proxyURL(url);
            } catch {}

            return originalOpen.call(
                this,
                method,
                url,
                ...rest
            );
        };

    // WebSocket
    const NativeWebSocket =
        window.WebSocket;

    window.WebSocket = function(url, protocols) {
        const proxied = proxyWS(url);

        if (protocols === undefined) {
            return new NativeWebSocket(proxied);
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

    // EventSource
    if (window.EventSource) {
        const NativeEventSource =
            window.EventSource;

        window.EventSource =
            function(url, options) {

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

    // sendBeacon
    if (navigator.sendBeacon) {
        const originalBeacon =
            navigator.sendBeacon.bind(navigator);

        navigator.sendBeacon = function(url, data) {
            return originalBeacon(
                proxyURL(url),
                data
            );
        };
    }

    // Links
    document.addEventListener(
        "click",
        event => {

            const link =
                event.target.closest?.("a[href]");

            if (!link) return;
            if (event.defaultPrevented) return;

            try {
                const absolute =
                    new URL(
                        link.getAttribute("href"),
                        TARGET_BASE
                    );

                if (
                    absolute.protocol === "http:" ||
                    absolute.protocol === "https:"
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
})();
</script>`;

    if (/<\/body>/i.test(html)) {
        html = html.replace(/<\/body>/i, injected + "</body>");
    } else {
        html += injected;
    }

    return html;
}

proxy.on("proxyReq", (proxyReq, req) => {
    // Force target servers to send uncompressed HTML so we can modify it
    proxyReq.setHeader("accept-encoding", "identity");

    // FIX: Spoof a real browser User-Agent so Google doesn't block the request as a bot
    proxyReq.setHeader("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");
    proxyReq.setHeader("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
    proxyReq.setHeader("accept-language", "en-US,en;q=0.9");

    const target = req._relayTarget;
    if (target) {
        proxyReq.setHeader("host", target.host);
        if (req.headers.origin) proxyReq.setHeader("origin", target.origin);
        if (req.headers.referer) proxyReq.setHeader("referer", target.origin + "/");
    }
});

proxy.on("proxyRes", async (proxyRes, req, res) => {
    const target = req._relayTarget;

    // FIX: Delete restrictive headers, including HSTS and Clear-Site-Data
    delete proxyRes.headers["x-frame-options"];
    delete proxyRes.headers["content-security-policy"];
    delete proxyRes.headers["content-security-policy-report-only"];
    delete proxyRes.headers["cross-origin-opener-policy"];
    delete proxyRes.headers["cross-origin-embedder-policy"];
    delete proxyRes.headers["cross-origin-resource-policy"];
    delete proxyRes.headers["strict-transport-security"];
    delete proxyRes.headers["report-to"];
    delete proxyRes.headers["nel"];
    delete proxyRes.headers["clear-site-data"];

    if (proxyRes.headers["set-cookie"]) {
        proxyRes.headers["set-cookie"] = proxyRes.headers["set-cookie"].map(cookie =>
            cookie.replace(/;\s*Domain=[^;]*/gi, "").replace(/;\s*SameSite=None/gi, "; SameSite=Lax")
        );
    }

    if (proxyRes.headers.location) {
        try {
            const location = new URL(proxyRes.headers.location, target.href);
            proxyRes.headers.location = relayURL(location.href);
        } catch {}
    }

    const contentType = proxyRes.headers["content-type"] || "";
    const chunks = [];

    proxyRes.on("data", chunk => chunks.push(chunk));

    proxyRes.on("end", () => {
        let body = Buffer.concat(chunks);

        if (contentType.includes("text/html")) {
            body = Buffer.from(
                rewriteHTML(body.toString("utf8"), target.href),
                "utf8"
            );
            proxyRes.headers["content-length"] = String(body.length);
        }

        delete proxyRes.headers["transfer-encoding"];

        res.writeHead(
            proxyRes.statusCode || 200,
            proxyRes.statusMessage,
            proxyRes.headers
        );
        res.end(body);
    });
});

proxy.on("error", (err, req, res) => {
    console.error("Proxy error:", err.message);
    if (res && !res.headersSent) {
        res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
    }
    if (res) res.end("Relay error: " + err.message);
});

function getTarget(req) {
    const requestURL = new URL(req.url, `http://${req.headers.host}`);
    const raw = requestURL.searchParams.get("url");
    if (!raw) throw new Error("Missing ?url=");
    return new URL(raw);
}

const server = http.createServer(async (req, res) => {
    // Basic CORS for iframe requests
    res.setHeader("Access-Control-Allow-Origin", "*");
    
    if (req.url === "/health") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true, allowedHosts: ALLOWED_HOSTS }));
        return;
    }

    // Proxy requests logic...
    if (req.url.startsWith("/relay")) {
        try {
            const target = getTarget(req);
            await validateTarget(target);
            req._relayTarget = target;
            req.url = target.pathname + target.search;
            
            proxy.web(req, res, { target: target.origin });
        } catch (err) {
            res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
            res.end(err.message);
        }
        return;
    }

    res.writeHead(404);
    res.end("Not found");
});

server.listen(PORT, "0.0.0.0", () => {
    console.log(`Relay: http://localhost:${PORT}`);
});