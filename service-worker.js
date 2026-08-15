// Minimal service worker — exists mainly to satisfy "installability" so the
// browser offers Add to Home Screen / Install app. Deliberately uses a
// network-first strategy for everything: it ALWAYS tries to fetch the
// latest version first, and only falls back to a cached copy if the
// network request fails (e.g. no internet). This avoids ever getting
// stuck showing an old cached version after an update — a real risk with
// service workers otherwise, and this project already updates often.
//
// IMPORTANT: fetch() alone still respects the browser's normal HTTP cache,
// which can silently serve a stale response even inside a "network-first"
// handler. {cache: 'no-store'} forces a truly fresh request every time.

const CACHE_NAME = 'qalam-shell-v2';
const SHELL_FILES = ['./index.html', './manifest.json', './icon-192.png', './icon-512.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_FILES)).catch(()=>{})
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n)))
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  // Only handle same-origin GET requests for the app shell — never intercept
  // calls to the AI/transcription APIs, which must always go live to network.
  if (event.request.method !== 'GET') return;
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  event.respondWith(
    fetch(event.request, { cache: 'no-store' })
      .then((response) => {
        const copy = response.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy)).catch(()=>{});
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});
