const CACHE_NAME = 'e2hat-v1';
const STATIC_ASSETS = [
    './',
    './index.html',
    './style.css',
    './protocol.js',
    './app.js',
    './icon.svg',
    'https://unpkg.com/vue@3/dist/vue.global.prod.js',
    'https://unpkg.com/js-ecutils@latest/dist/web/min.js',
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(STATIC_ASSETS))
            .then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys().then((names) =>
            Promise.all(names.map((n) => n !== CACHE_NAME ? caches.delete(n) : undefined))
        ).then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    const url = new URL(event.request.url);
    if (url.pathname.endsWith('/ws')) return;

    event.respondWith(
        caches.match(event.request).then((cached) => {
            const fetchPromise = fetch(event.request).then((response) => {
                if (response && response.status === 200) {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
                }
                return response;
            }).catch(() => cached);
            return cached || fetchPromise;
        })
    );
});
