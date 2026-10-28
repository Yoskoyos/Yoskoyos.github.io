// CCTV Monitor — service worker
// Pagina se ia MEREU de pe internet, ocolind memoria browserului (GitHub Pages permite păstrarea ei 10 min),
// iar ultima versiune rămâne salvată doar pentru folosire fără internet.
const CACHE = 'yca-cctv-v2';

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => c.add(new Request('/index.html', { cache: 'reload' })))
      .catch(() => {})
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;          // proxy NVR, Telegram etc. — nu ne atingem

  const isPage = req.mode === 'navigate' || url.pathname === '/' || url.pathname.endsWith('.html');
  if (isPage) {
    e.respondWith(
      fetch(url.pathname + url.search, { cache: 'no-cache', credentials: 'same-origin' })
        .then(res => {
          if (res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put('/index.html', copy)); }
          return res;
        })
        .catch(() => caches.match('/index.html'))
    );
    return;
  }
  // iconițe, manifest: internet, cu rezervă din cache
  e.respondWith(fetch(req).catch(() => caches.match(req)));
});
