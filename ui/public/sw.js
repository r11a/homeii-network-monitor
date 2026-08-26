const CACHE = 'homeii-shell-v7.0.0-clarity'
const SHELL = ['./', './manifest.webmanifest', './icons/homeii-192.png']

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()))
})

self.addEventListener('activate', (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key)))).then(() => self.clients.claim()))
})

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET' || new URL(event.request.url).pathname.includes('/api/')) return
  event.respondWith(fetch(event.request).then((response) => {
    const copy = response.clone()
    caches.open(CACHE).then((cache) => cache.put(event.request, copy))
    return response
  }).catch(() => caches.match(event.request).then((cached) => cached || caches.match('./'))))
})

self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  event.waitUntil(self.clients.matchAll({type: 'window', includeUncontrolled: true}).then((clients) => {
    if (clients[0]) return clients[0].focus().then(() => clients[0].navigate('./#/alerts'))
    return self.clients.openWindow('./#/alerts')
  }))
})
