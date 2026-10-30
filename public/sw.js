// PlotManager service worker
// - Τα δεδομένα (/api) δεν αποθηκεύονται ποτέ: πάντα από τον διακομιστή.
// - Η σελίδα φορτώνεται πρώτα από το δίκτυο, ώστε κάθε νέα έκδοση να φαίνεται αμέσως·
//   από την cache μόνο όταν δεν υπάρχει σύνδεση.
// - Οι βιβλιοθήκες του cdnjs (σταθερές εκδόσεις) κρατιούνται στην cache.
const CACHE = 'plotmanager-v4';
const SHELL = ['/', '/manifest.webmanifest', '/favicon.svg', '/icons/icon-192.png', '/icons/icon-512.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys()
    .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
    .then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin === location.origin && url.pathname.startsWith('/api/')) return;     // δεδομένα: ποτέ cache
  if (req.mode === 'navigate') {                                                        // σελίδα: δίκτυο πρώτα
    // στην cache μόνο η αρχική σελίδα και μόνο επιτυχημένη απάντηση (όχι σελίδα σφάλματος 404/500)
    e.respondWith(fetch(req).then((r) => { if (r.ok && url.pathname === '/') { const c = r.clone(); caches.open(CACHE).then((x) => x.put('/', c)); } return r; })
      .catch(() => caches.match('/')));
    return;
  }
  const cdn = url.hostname === 'cdnjs.cloudflare.com';
  if (url.origin === location.origin || cdn) {                                          // στατικά: cache, ενημέρωση στο παρασκήνιο
    e.respondWith(caches.match(req).then((hit) => {
      const net = fetch(req).then((r) => { if (r.ok) { const c = r.clone(); caches.open(CACHE).then((x) => x.put(req, c)); } return r; }).catch(() => hit);
      return hit || net;
    }));
  }
  // πλακίδια χαρτών (OSM, Κτηματολόγιο): κανονικά από το δίκτυο
});
