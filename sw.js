// Empower PT Scribe — service worker
// Only handles push notifications (no offline caching). This file must be
// served from the SAME path/origin as index.html (e.g. alongside it in the
// repo root) so its scope covers the whole app.

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  let data = { title: 'Empower', body: 'You have an update.' };
  try {
    if (event.data) data = event.data.json();
  } catch (e) {
    if (event.data) data.body = event.data.text();
  }
  const options = {
    body: data.body || '',
    tag: 'empower-appointment',
    renotify: true,
  };
  event.waitUntil(self.registration.showNotification(data.title || 'Empower', options));
});

// Tapping the notification focuses an already-open tab if there is one,
// otherwise opens the app.
self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if ('focus' in client) return client.focus();
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow('./');
      }
    })
  );
});
