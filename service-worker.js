/* =============================================================
   CyberShield AI  -  service-worker.js
   Offline caching so the installed PWA works without a network.
   Strategy:
     - Pre-cache the app shell on install.
     - Cache-first for same-origin GET requests (fast + offline).
     - Fall back to cached index.html for navigations when offline.
   NOTE: Service workers only run over http(s) or http://localhost
         (they do NOT run from file://). Use serve.ps1 / serve.bat
         or a host like Netlify / GitHub Pages.
   ============================================================= */

const CACHE = "cybershield-v1";

/* App shell files to pre-cache (relative paths keep it portable) */
const ASSETS = [
  "./",
  "./index.html",
  "./style.css",
  "./script.js",
  "./pwa.js",
  "./manifest.json",
  "./assets/favicon.svg",
  "./assets/icon-192.png",
  "./assets/icon-512.png",
  "./assets/icon-maskable-512.png",
  "./assets/apple-touch-icon.png"
];

/* Install: pre-cache the shell (ignore individual failures) */
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) =>
      Promise.all(
        ASSETS.map((url) =>
          cache.add(url).catch(() => console.warn("[SW] skip cache:", url))
        )
      )
    )
  );
  self.skipWaiting();
});

/* Activate: remove old caches */
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

/* Fetch: cache-first, then network; offline navigations fall back to index.html */
self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  event.respondWith(
    caches.match(req).then((cached) => {
      if (cached) return cached;
      return fetch(req)
        .then((res) => {
          // cache same-origin successful responses for next time
          if (res.ok && new URL(req.url).origin === self.location.origin) {
            const copy = res.clone();
            caches.open(CACHE).then((c) => c.put(req, copy));
          }
          return res;
        })
        .catch(() => {
          // offline: for page navigations, serve the app shell
          if (req.mode === "navigate") return caches.match("./index.html");
        });
    })
  );
});
