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
    tag: data.tag || ('musaed-' + Date.now()),
    renotify: true,
    icon: './icon-192.png',
  };
  event.waitUntil(Promise.all([
    self.registration.showNotification(data.title || 'Empower', options),
    saveNotif(data),
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((cs) => cs.forEach((c) => c.postMessage({ type: 'musaed-push', title: data.title || '', body: data.body || '' }))),
  ]));
});

// Every push is also kept on the device (last 7 days, 60 max) so the in-app bell can list it.
function saveNotif(d) {
  return new Promise((resolve) => {
    try {
      const r = indexedDB.open('musaed-notifs', 1);
      r.onupgradeneeded = () => r.result.createObjectStore('items', { keyPath: 'id', autoIncrement: true });
      r.onerror = () => resolve();
      r.onsuccess = () => {
        const db = r.result;
        try {
          const tx = db.transaction('items', 'readwrite');
          tx.objectStore('items').add({ title: String(d.title || ''), body: String(d.body || ''), at: Date.now() });
          tx.oncomplete = () => { db.close(); resolve(); };
          tx.onerror = () => { db.close(); resolve(); };
        } catch (e) { db.close(); resolve(); }
      };
    } catch (e) { resolve(); }
  });
}

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
