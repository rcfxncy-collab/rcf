// Small service worker: keeps the shop pages and images quick and lets the home page open without internet.
// It never touches /api/ or manager.html, so billing and live data always come straight from the server.
const VER = 'rcf-site-v1', PAGES = ['/', '/product.html', '/checkbill.html'];
self.addEventListener('install', e => { e.waitUntil(caches.open(VER).then(c => c.addAll(PAGES).catch(() => {})).then(() => self.skipWaiting())); });
self.addEventListener('activate', e => { e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== VER).map(k => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', e => {
  const r = e.request, u = new URL(r.url);
  if (r.method !== 'GET' || u.origin !== location.origin || u.pathname.startsWith('/api/') || u.pathname === '/manager.html' || u.pathname === '/sw.js') return;
  if (r.mode === 'navigate') {   // pages: newest from the network, saved copy when offline
    e.respondWith(fetch(r).then(res => { const cp = res.clone(); caches.open(VER).then(c => c.put(r, cp)); return res; }).catch(() => caches.match(r).then(m => m || caches.match('/'))));
  } else if (u.pathname.startsWith('/public/')) {   // images: saved copy first
    e.respondWith(caches.match(r).then(m => m || fetch(r).then(res => { const cp = res.clone(); caches.open(VER).then(c => c.put(r, cp)); return res; })));
  }
});
