// Hält die Seite auf dem Handy vor, damit sie auch ohne Empfang lädt.
// Die Seite selbst wird immer zuerst frisch geladen (dann ist sie aktuell). Kommt nach 4 Sekunden
// keine Antwort oder gibt es kein Netz, wird die gespeicherte Fassung gezeigt.
// Gespeichert wird nur, was ohnehin öffentlich ist: die verschlüsselte Seite und die Schriften.

const CACHE = "rallye-v1";
const PAGE = "./";
const ASSETS = [PAGE, "fonts/barlow-condensed-600.woff2", "fonts/barlow-condensed-700.woff2", "fonts/public-sans.woff2"];
const WAIT_MS = 4000;

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET" || new URL(req.url).origin !== self.location.origin) return;
  if (req.mode === "navigate") e.respondWith(pageFirstFromNetwork(req));
  else e.respondWith(caches.match(req).then((hit) => hit || fetch(req)));
});

function pageFirstFromNetwork(req) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (res) => { if (!done && res) { done = true; resolve(res); } };
    const fromCache = () => caches.match(PAGE);

    fetch(req, { cache: "no-cache" }).then((res) => {
      if (res.ok) {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(PAGE, copy));
      }
      finish(res);
    }, () => {
      fromCache().then((hit) => finish(hit || Response.error()));
    });

    setTimeout(() => { if (!done) fromCache().then(finish); }, WAIT_MS);
  });
}
