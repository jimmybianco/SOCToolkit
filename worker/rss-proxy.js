// SOC Toolkit RSS proxy — Cloudflare Worker.
//
// GET /?url=<encoded feed URL> fetches the feed server side and returns the
// raw XML with CORS headers, so the site can read feeds whose publishers
// don't send CORS themselves. The page parses the XML (app.js, parseFeedXml).
//
// Deploy: Cloudflare dashboard → Workers & Pages → Create → Worker, paste
// this file, deploy, then set RSS_PROXY in app.js to the worker's URL.

const ALLOWED_ORIGINS = [
    "https://soctoolkit.com",
    "https://www.soctoolkit.com",
];
const CACHE_SECONDS = 30 * 60;          // edge cache per feed URL
const MAX_BYTES     = 5 * 1024 * 1024;  // refuse anything bigger

// "null" is index.html opened from disk (file://), for local testing.
function isAllowedOrigin(origin) {
    return ALLOWED_ORIGINS.includes(origin) || origin === "null"
        || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
}

function corsHeaders(origin) {
    const allowed = isAllowedOrigin(origin);
    return {
        "Access-Control-Allow-Origin": allowed ? origin : ALLOWED_ORIGINS[0],
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Vary": "Origin",
    };
}

function reply(status, body, origin, extra = {}) {
    return new Response(body, {
        status,
        headers: {
            "Content-Type": "text/plain; charset=utf-8",
            // The site reads responses with fetch(); a browser opening one
            // directly (e.g. an SVG or XHTML "feed") must never run it.
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "X-Content-Type-Options": "nosniff",
            ...corsHeaders(origin),
            ...extra,
        },
    });
}

export default {
    async fetch(request) {
        const origin = request.headers.get("Origin") || "";
        if (request.method === "OPTIONS") return reply(204, null, origin);
        if (request.method !== "GET")     return reply(405, "Method not allowed", origin);
        // Only our site may use the proxy. Origin can be faked outside a
        // browser, so this just keeps other sites and casual use from
        // spending the quota or fetching through us.
        if (!isAllowedOrigin(origin))     return reply(403, "Forbidden", origin);

        let target;
        try { target = new URL(new URL(request.url).searchParams.get("url") || ""); }
        catch { return reply(400, "Missing or invalid ?url=", origin); }
        if (!/^https?:$/.test(target.protocol)) return reply(400, "Only http(s) URLs", origin);

        let upstream;
        try {
            upstream = await fetch(target.toString(), {
                headers: {
                    "User-Agent": "Mozilla/5.0 (compatible; SOCToolkit-RSS/1.0; +https://soctoolkit.com)",
                    "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml;q=0.9, */*;q=0.8",
                },
                redirect: "follow",
                cf: { cacheTtl: CACHE_SECONDS, cacheEverything: true },
            });
        } catch {
            return reply(502, "Upstream fetch failed", origin);
        }
        if (!upstream.ok) return reply(502, `Upstream returned ${upstream.status}`, origin);

        const declared = Number(upstream.headers.get("Content-Length") || 0);
        if (declared > MAX_BYTES) return reply(502, "Feed too large", origin);
        const body = await upstream.text();
        if (body.length > MAX_BYTES) return reply(502, "Feed too large", origin);

        // Only pass through things that look like a feed, so the worker
        // can't be used as a general-purpose proxy for HTML pages etc.
        const head = body.slice(0, 2048).replace(/^﻿/, "").trimStart();
        if (!/^<(\?xml|rss|feed|rdf:RDF)\b/i.test(head) || /^<!doctype html|<html\b/i.test(head)) {
            return reply(502, "Not an RSS/Atom feed", origin);
        }

        return reply(200, body, origin, {
            "Content-Type": "application/xml; charset=utf-8",
            "Cache-Control": `public, max-age=${CACHE_SECONDS}`,
        });
    },
};
