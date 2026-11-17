/*
  coi-serviceworker — fallback cross-origin isolation for static hosts that
  cannot set COOP/COEP response headers (S3 / CloudFront / GitHub Pages).

  Registers a service worker that re-serves every response with
  Cross-Origin-Opener-Policy: same-origin and
  Cross-Origin-Embedder-Policy: credentialless, then reloads the page so
  `self.crossOriginIsolated === true` (required for SharedArrayBuffer transfer
  to the WebClient workers).

  If the host already sends the headers, this script does nothing.

  The reload is bounded (max 3 attempts) and self-healing: after a reload the
  page re-checks isolation, so a reload that races the worker's activation is
  retried instead of leaving the tab permanently non-isolated.
*/
if (typeof window === "undefined") {
  // ---------------------------------------------------------------- worker
  self.addEventListener("install", () => self.skipWaiting());
  self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));

  // ------------------------------------------------------------------
  // Optional API proxy.
  //
  // Roblox's API hosts send no Access-Control-Allow-Origin, so the engine
  // cannot read their responses from a page on our own origin. When the page
  // supplies a proxy URL (see rbx-config.js), we transparently route the
  // engine's roblox.com API calls through it and hand the response back.
  // Because the response comes from a service worker, the browser does not
  // re-apply the cross-origin check, so this genuinely unblocks them.
  // ------------------------------------------------------------------
  const API_HOSTS = [
    "apis.roblox.com",
    "economy.roblox.com",
    "locale.roblox.com",
    "gamejoin.roblox.com",
    "users.roblox.com",
    "thumbnails.roblox.com",
    "groups.roblox.com",
    "avatar.roblox.com",
    "catalog.roblox.com",
    "accountsettings.roblox.com",
    "auth.roblox.com",
    "clientsettings.roblox.com",
    "clientsettingscdn.roblox.com",
    "games.roblox.com",
    "presence.roblox.com",
    "friends.roblox.com",
    "inventory.roblox.com",
    "badges.roblox.com",
    "develop.roblox.com",
    "notifications.roblox.com",
    "chat.roblox.com",
    "contacts.roblox.com",
    "accountinformation.roblox.com",
    "assetdelivery.roblox.com",
    "translations.roblox.com",
    "gameinternationalization.roblox.com",
    "metrics.roblox.com",
    "ephemeralcounters.api.roblox.com",
    "ecsv2.roblox.com",
    "tracing.roblox.com",
    "telemetry.roblox.com",
    "data.roblox.com",
    "points.roblox.com",
    "premiumfeatures.roblox.com",
    "billing.roblox.com",
    "adconfiguration.roblox.com",
    "trades.roblox.com",
    "www.roblox.com",
  ];

  let CFG = { proxyUrl: "", cookie: "" };
  let cfgLoaded = false;

  function loadCfg() {
    // Already known (set by a message from the page, or a previous IDB read).
    if (cfgLoaded || CFG.proxyUrl || CFG.cookie) return Promise.resolve(CFG);
    return new Promise((resolve) => {
      let done = false;
      const finish = (v) => {
        if (done) return;
        done = true;
        if (v) {
          CFG = Object.assign(CFG, v);
          // Only cache a *successful* read. Caching a timeout would pin the
          // worker to "no proxy" for the rest of its life.
          cfgLoaded = true;
        }
        resolve(CFG);
      };
      try {
        const rq = indexedDB.open("rbxcfg", 1);
        rq.onupgradeneeded = () => {
          try { rq.result.createObjectStore("kv"); } catch (e) {}
        };
        rq.onerror = () => finish(null);
        rq.onsuccess = () => {
          try {
            const g = rq.result.transaction("kv", "readonly").objectStore("kv").get("cfg");
            g.onsuccess = () => finish(g.result || null);
            g.onerror = () => finish(null);
          } catch (e) { finish(null); }
        };
        setTimeout(() => finish(null), 2000);
      } catch (e) { finish(null); }
    });
  }

  self.addEventListener("message", (event) => {
    const d = event.data;
    if (d && d.type === "rbx-config" && d.cfg) {
      CFG = Object.assign(CFG, d.cfg);
      cfgLoaded = true;
    }
  });

  function isApiHost(hostname) {
    const h = hostname.toLowerCase();
    return API_HOSTS.indexOf(h) !== -1;
  }

  /* Hosts whose responses come from a folder in this build, not from Roblox.
     host  = the cross-origin hostname the engine asks for
     local = the folder that mirrors that host's paths
     path  = only rewrite matching paths (omit to rewrite the whole host) */
  const LOCAL_REWRITES = [
    {
      host: "gameinternationalization.roblox.com",
      local: "gameinternationalization",
      path: /^\/v1\/user-localization-settings\/player-choice\/\d+\/?$/,
    },
  ];

  function localRewrite(u) {
    if (!u) return null;
    const h = u.hostname.toLowerCase();
    for (let i = 0; i < LOCAL_REWRITES.length; i++) {
      const rule = LOCAL_REWRITES[i];
      if (h !== rule.host) continue;
      if (rule.path && !rule.path.test(u.pathname)) continue;
      return self.location.origin + "/" + rule.local + u.pathname + u.search;
    }
    return null;
  }

  async function proxyThrough(request, cfg) {
    const target = cfg.proxyUrl + "/p?url=" + encodeURIComponent(request.url);
    const headers = new Headers();
    // Forward the content type so POST bodies are parsed upstream.
    const ct = request.headers.get("content-type");
    if (ct) headers.set("Content-Type", ct);
    const accept = request.headers.get("accept");
    if (accept) headers.set("Accept", accept);
    // The session cookie lives in config, not in this origin's cookie jar.
    if (cfg.cookie) headers.set("Cookie", cfg.cookie);

    const init = {
      method: request.method,
      headers,
      credentials: "omit",
      redirect: "follow",
      mode: "cors",
    };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = await request.clone().arrayBuffer();
    }
    const res = await fetch(target, init);
    const buf = await res.arrayBuffer();
    const out = new Headers();
    const rct = res.headers.get("content-type");
    if (rct) out.set("Content-Type", rct);
    return new Response(buf, { status: res.status, statusText: res.statusText, headers: out });
  }

  self.addEventListener("fetch", function (event) {
    const r = event.request;
    if (r.cache === "only-if-cached" && r.mode !== "same-origin") return;

    // Never touch cross-origin requests: re-wrapping them would drop their
    // opaque/CORS status and break third-party loads.
    let sameOrigin = false;
    let hostname = "";
    let parsedUrl = null;
    try {
      const u = new URL(r.url);
      parsedUrl = u;
      sameOrigin = u.origin === self.location.origin;
      hostname = u.hostname;
    } catch (e) {
      sameOrigin = false;
    }

    if (!sameOrigin) {
      // Hosts answered from a folder in this build instead of from Roblox.
      // e.g. gameinternationalization.roblox.com/v1/user-localization-settings/
      //      player-choice/1517500825  ->  ./gameinternationalization/...
      const local = localRewrite(parsedUrl);
      if (local) {
        event.respondWith(
          fetch(local).then((res) => {
            if (res.status !== 404) return res;
            // No file for this id: fall back to the proxy, then the network.
            return loadCfg().then((cfg) => {
              if (!cfg.proxyUrl) return fetch(r);
              return proxyThrough(r, cfg).catch(() => fetch(r));
            });
          })
        );
        return;
      }

      // Cross-origin: only intervene for Roblox API hosts, and only when the
      // page has configured a proxy.
      if (!isApiHost(hostname)) return;
      event.respondWith(
        loadCfg().then((cfg) => {
          if (!cfg.proxyUrl) return fetch(r);
          return proxyThrough(r, cfg).catch((e) => {
            console.warn("[coi] proxy failed for " + r.url + ": " + e.message);
            return fetch(r);
          });
        })
      );
      return;
    }

    const request = r.mode === "no-cors" ? new Request(r, { mode: "same-origin" }) : r;

    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response.status === 0 || response.type === "opaque") return response;
          // Only genuine 3xx redirects must be passed through untouched:
          // re-wrapping a redirect response throws. A response that merely
          // *followed* a redirect is fine to rebuild (and rebuilding clears
          // its `redirected` flag, which is what we want).
          if (response.status >= 300 && response.status < 400) return response;

          // If the origin already sends the isolation headers (server.js does),
          // hand the response back untouched. Re-wrapping a navigation response
          // is what produced the "Failed to fetch" cascade in the console.
          const hasCoop = response.headers.get("Cross-Origin-Opener-Policy");
          const hasCoep = response.headers.get("Cross-Origin-Embedder-Policy");
          if (hasCoop && hasCoep) return response;
          if (r.mode === "navigate") return response;

          const headers = new Headers(response.headers);
          // credentialless (not require-corp): the engine loads its Next.js
          // chunks straight from play.roblox.com, and Roblox's CDN sends no
          // Cross-Origin-Resource-Policy / CORS header, so require-corp would
          // block them with ERR_BLOCKED_BY_RESPONSE.NotSameOrigin...  Both
          // modes still give us crossOriginIsolated === true.
          headers.set("Cross-Origin-Embedder-Policy", "credentialless");
          headers.set("Cross-Origin-Opener-Policy", "same-origin");
          headers.set("Cross-Origin-Resource-Policy", "cross-origin");
          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: headers,
          });
        })
        .catch(async (e) => {
          // A single transient failure (server restarting, socket reset while
          // the proxy was mid-flight) is not worth failing the resource over.
          // Retry once after a short pause before giving up.
          try {
            await new Promise((r2) => setTimeout(r2, 300));
            return await fetch(request);
          } catch (e2) {
            // Never re-issue endlessly: it fails the same way and the second
            // rejection surfaces as an uncaught error.
            console.error("[coi] fetch failed for " + r.url + ": " + e2.message);
            // Only a navigation can meaningfully display an explanation. For
            // scripts, styles, images and XHR/fetch a synthetic 504 is worse
            // than useless: it turns a transient blip into a hard error that
            // shows up as "Failed to load resource: 504" and can wedge the
            // page. Hand back a plain network error instead, which callers
            // already handle as a normal failure.
            if (r.mode !== "navigate") return Response.error();
            return new Response(
              "The local server did not answer " + r.url + "\n\n" +
              "This usually means `node server.js` is no longer running.\n" +
              "Restart it with:  cd RobloxWeb && node server.js\n",
              { status: 504, statusText: "Gateway Timeout", headers: { "Content-Type": "text/plain; charset=utf-8" } }
            );
          }
        })
    );
  });
} else {
  // ---------------------------------------------------------------- window
  (async function () {
    if (!window.isSecureContext || !("serviceWorker" in navigator)) {
      if (!window.crossOriginIsolated) {
        console.warn("[coi] Service workers unavailable; cannot enable cross-origin isolation.");
      }
      return;
    }

    const script = document.currentScript;
    const base = script ? script.src : new URL("coi-serviceworker.js", location.href).href;
    // Version-stamped URL: a stale registration from an older deploy is
    // replaced by a brand-new worker instead of being silently reused.
    const SW_V = "6";
    const swUrl = base + (base.indexOf("?") === -1 ? "?v=" + SW_V : "&v=" + SW_V);

    // Full repair: drop every worker + cache for this origin, then register
    // clean and reload. Exposed so the isolation-guard card can offer it as a
    // one-click button when a stale worker is the reason isolation never lands.
    window.__coiRepair = async function () {
      try {
        const regs = await navigator.serviceWorker.getRegistrations();
        await Promise.all(regs.map((r) => r.unregister().catch(() => {})));
      } catch (e) {}
      try {
        if (window.caches) {
          const keys = await caches.keys();
          await Promise.all(keys.map((k) => caches.delete(k).catch(() => {})));
        }
      } catch (e) {}
      try {
        sessionStorage.removeItem("coi-reload-count");
        sessionStorage.removeItem("coi-nuke-count");
      } catch (e) {}
      try {
        await navigator.serviceWorker.register(swUrl, { updateViaCache: "none" });
        await navigator.serviceWorker.ready;
      } catch (e) {
        console.warn("[coi] re-registration failed", e);
      }
      location.reload();
    };

    if (window.crossOriginIsolated) {
      // The host already sends COOP/COEP, so isolation is fine. We still
      // register the worker: it is what routes Roblox API calls through the
      // optional CORS proxy (see rbx-config.js). No reload needed.
      try {
        sessionStorage.removeItem("coi-reload-count");
        sessionStorage.removeItem("coi-nuke-count");
        sessionStorage.removeItem("coi-autoheal");
      } catch (e) {}
      try {
        await navigator.serviceWorker.register(swUrl, { updateViaCache: "none" });
        await navigator.serviceWorker.ready;
      } catch (e) {
        console.warn("[coi] proxy worker registration failed", e);
      }
      return;
    }

    let attempts = 0;
    let nukes = 0;
    try { attempts = Number(sessionStorage.getItem("coi-reload-count") || "0") || 0; } catch (e) {}
    try { nukes = Number(sessionStorage.getItem("coi-nuke-count") || "0") || 0; } catch (e) {}

    if (attempts >= 3) {
      // Reloading alone did not help, which almost always means a stale or
      // half-broken registration is holding the scope. Tear it all down once.
      if (nukes < 1) {
        console.warn("[coi] isolation still missing after " + attempts + " reloads \u2014 resetting the worker");
        try { sessionStorage.setItem("coi-nuke-count", "1"); } catch (e) {}
        await window.__coiRepair();
        return;
      }
      console.error(
        "[coi] Still not cross-origin isolated after " + attempts +
        " reloads and a full worker reset. Something outside the page is " +
        "stripping COOP/COEP \u2014 use the Repair button on the error card."
      );
      window.__coiGaveUp = true;
      return;
    }

    try {
      await navigator.serviceWorker.register(swUrl, { updateViaCache: "none" });
      await navigator.serviceWorker.ready;

      // Wait for the worker to actually control this client. `ready` only
      // guarantees an *active* worker, not that it has claimed this page.
      if (!navigator.serviceWorker.controller) {
        await new Promise((resolve) => {
          const done = () => { clearTimeout(t); resolve(); };
          const t = setTimeout(done, 4000);
          navigator.serviceWorker.addEventListener("controllerchange", done, { once: true });
        });
      }

      // Give the browser a beat so the next navigation is definitely
      // intercepted by the worker's fetch handler.
      try { sessionStorage.setItem("coi-reload-count", String(attempts + 1)); } catch (e) {}
      setTimeout(() => window.location.reload(), 150);
    } catch (e) {
      console.error("[coi] registration failed", e);
    }
  })();
}
