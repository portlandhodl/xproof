// coi-sw.js — makes the page cross-origin isolated on static hosts (GitHub Pages can't set
// headers). Same-origin responses get COOP/COEP added, which enables SharedArrayBuffer and
// therefore multi-threaded WASM proving. Cross-origin requests (mempool.space, the CRS CDN)
// pass through untouched; they are CORS-enabled, which COEP require-corp accepts.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.cache === "only-if-cached" && req.mode !== "same-origin") return;
  if (new URL(req.url).origin !== self.location.origin) return;
  event.respondWith(
    fetch(req).then((res) => {
      if (res.status === 0) return res;
      const headers = new Headers(res.headers);
      headers.set("Cross-Origin-Opener-Policy", "same-origin");
      headers.set("Cross-Origin-Embedder-Policy", "require-corp");
      return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
    })
  );
});
