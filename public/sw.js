self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => {}); // keeps the app installable

self.addEventListener('push', (event) => {
  let d = { title: 'CyberWatch alert', body: 'New security update', url: '/' };
  try { d = { ...d, ...event.data.json() }; } catch {}
  event.waitUntil(self.registration.showNotification(d.title, {
    body: d.body,
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    tag: d.tag,
    renotify: true,
    requireInteraction: /HIGH/.test(d.title),
    data: { url: d.url }
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || '/';
  event.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
    for (const c of list) if ('focus' in c) { c.navigate(url); return c.focus(); }
    return self.clients.openWindow(url);
  }));
});
