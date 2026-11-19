/* Prahari service worker: the console works offline for the shell, live data always fresh. */
const CACHE = 'prahari-v3';
const SHELL = ['/', '/manifest.json', '/static/icon-192.png', '/static/icon-512.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  // Only the app shell is cached: never live data (/api/), sign-in/out or SSO callbacks.
  if (event.request.method !== 'GET' || url.origin !== self.location.origin ||
      SHELL.indexOf(url.pathname) < 0) {
    return;
  }
  event.respondWith(
    fetch(event.request)
      .then((resp) => {
        const copy = resp.clone();
        caches.open(CACHE).then((c) => c.put(event.request, copy)).catch(() => {});
        return resp;
      })
      .catch(() => caches.match(event.request).then((hit) => hit || caches.match('/')))
  );
});
