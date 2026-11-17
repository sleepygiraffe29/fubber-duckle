#!/usr/bin/env node
/*
  server.js — one-command local host for this self-hosted Roblox WebClient.

  What it does
  ------------
  1. Serves the build with COOP/COEP so SharedArrayBuffer works natively.
  2. Proxies Roblox's APIs on the same origin (/api/p?url=...) so there is no
     CORS and no Private Network Access prompt.
  3. Detects the Roblox account that is already signed in on *this* browser,
     by reading the local Chromium/Chrome/Edge/Brave/Firefox cookie store,
     decrypting .ROBLOSECURITY, and validating it against
     users.roblox.com/v1/users/authenticated.
  4. Keeps that session server-side (and injects it into client.html) so the
     WebClient can call gamejoin.roblox.com and join any experience the
     account is allowed to join.

  Usage
  -----
      node server.js
      PORT=3000 node server.js
      RBX_COOKIE=".ROBLOSECURITY=..." node server.js   # skip detection
      CHROME_PROFILE_DIR=/path/to/Profile node server.js

  Then open http://localhost:3000/
*/

"use strict";

const http = require("http");
const https = require("https");
const fs = require("fs");
const os = require("os");
const path = require("path");
const zlib = require("zlib");
const crypto = require("crypto");
const { URL } = require("url");

/* ---------------------------------------------------------------- safety net

   Every /api handler is an async IIFE. If one of them throws, Node's default
   behaviour is to terminate the process, which takes the whole page down with
   it: the service worker then reports "Failed to fetch" for every request and
   the UI looks like a CORS problem when it is really a dead server.

   Log and keep serving instead. A failed request is recoverable; a dead
   process is not.
--------------------------------------------------------------------------- */
process.on("unhandledRejection", (err) => {
  console.error("[server] unhandled rejection (kept alive):", err && err.stack ? err.stack : err);
});
process.on("uncaughtException", (err) => {
  console.error("[server] uncaught exception (kept alive):", err && err.stack ? err.stack : err);
});

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
// Next.js assetPrefix of the Roblox build. Requests below this path are served
// from disk when present, otherwise proxied to play.roblox.com.
const ASSET_PREFIX = "038e4bd621bee962e64ed84fac16608407267adc";
const BUILD_ID = "2026-11-03-join-diagnostics";

/*
 * Injected into the engine's Web Worker (stub.js) before WebClient.js is
 * imported. The worker is same-origin with this server, so a relative /api/p
 * URL works and the server attaches the .ROBLOSECURITY session itself.
 *
 * Without this the engine's XMLHttpRequests leave the worker cross-origin
 * carrying this page's Origin header; Roblox refuses them and the engine logs
 * "HttpError: Unknown url" followed by "joinGameFailed".
 */
const ENGINE_WORKER_SHIM = `
  // ---- rbx worker proxy shim (injected by server.js) ----
  (function () {
    var PROXY = "/api/p?url=";
    var HOSTS = [".roblox.com", ".rbxcdn.com", ".robloxlabs.com"];
    var SKIP = ["setup.rbxcdn.com", "play.roblox.com"];
    function shouldProxy(u) {
      var url;
      try { url = new URL(u, self.location.href); } catch (e) { return false; }
      if (url.protocol !== "https:" && url.protocol !== "http:") return false;
      var h = url.hostname.toLowerCase();
      for (var i = 0; i < SKIP.length; i++) {
        if (h === SKIP[i] || h.endsWith("." + SKIP[i])) return false;
      }
      for (var j = 0; j < HOSTS.length; j++) {
        if (h === HOSTS[j].slice(1) || h.endsWith(HOSTS[j])) return true;
      }
      return false;
    }
    function proxify(u) {
      return PROXY + encodeURIComponent(new URL(u, self.location.href).href);
    }
    // ---- XMLHttpRequest (this is what the wasm engine actually uses) ----
    var nativeOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function (method, url) {
      var args = Array.prototype.slice.call(arguments);
      try {
        if (url && shouldProxy(url)) {
          args[1] = proxify(url);
          this.__rbxProxied = true;
        }
      } catch (e) {}
      return nativeOpen.apply(this, args);
    };
    // ---- fetch (used by some engine helpers) ----
    var nativeFetch = self.fetch;
    if (nativeFetch) {
      self.fetch = function (input, init) {
        try {
          var url = typeof input === "string" ? input : (input && input.url);
          if (url && shouldProxy(url)) {
            var opts = Object.assign({}, init || {});
            delete opts.credentials;
            if (typeof Request !== "undefined" && input instanceof Request && !init) {
              opts.method = input.method;
              opts.body = input.body;
              opts.headers = input.headers;
            }
            return nativeFetch.call(this, proxify(url), opts);
          }
        } catch (e) {}
        return nativeFetch.apply(this, arguments);
      };
    }
  })();
`;
const SESSION_FILE = path.join(ROOT, ".rbx-session.json");
const INSTALL_ID_FILE = path.join(ROOT, ".rbx-install-id");

/* ---- stale / foreign session guard ----------------------------------------
   A .rbx-session.json that did not originate on THIS install must never be
   trusted. Zips of this project have been passed around with somebody else's
   live cookie baked in, which made the app silently sign in as the wrong
   account. We stamp every session we write with a per-install random id and
   refuse (and delete) anything that doesn't match. */

/* Accounts known to have leaked inside distributed copies of this project.
   Their cached sessions are always discarded, even on the machine that
   created them, because the credential is public. */
const LEAKED_USER_IDS = new Set([1517500825]);

function installId() {
  try {
    const existing = fs.readFileSync(INSTALL_ID_FILE, "utf8").trim();
    if (/^[a-f0-9]{32}$/.test(existing)) return existing;
  } catch (e) {
    /* not created yet */
  }
  const id = crypto.randomBytes(16).toString("hex");
  try {
    fs.writeFileSync(INSTALL_ID_FILE, id + "\n", { mode: 0o600 });
    try { fs.chmodSync(INSTALL_ID_FILE, 0o600); } catch (e) {}
  } catch (e) {
    console.warn("[auth] could not persist install id:", e.message);
  }
  return id;
}

const INSTALL_ID = installId();

function purgeSessionFile(reason) {
  try {
    fs.unlinkSync(SESSION_FILE);
    console.log("[auth] discarded " + path.basename(SESSION_FILE) + ": " + reason);
  } catch (e) {
    /* nothing to remove */
  }
}

const ALLOW_HOSTS = (process.env.ALLOW_HOSTS || "roblox.com,robloxlabs.com,rbxcdn.com")
  .split(",")
  .map((s) => s.trim().toLowerCase())
  .filter(Boolean);
const ALLOW_ANY = ALLOW_HOSTS.includes("*");

/* ---- local overrides -------------------------------------------------------
   Some engine calls are answered from disk instead of being sent to Roblox.
   The files live under the same path the engine would request, e.g.

     gameinternationalization/v1/user-localization-settings/player-choice/1517500825

   so the folder itself is the override table: the filename is the user id and
   the body is the JSON to return. Anything not present on disk falls back to
   the numeric "0" file, then to PLAYER_CHOICE_DEFAULT.
--------------------------------------------------------------------------- */
const OVERRIDE_ROOT = path.join(ROOT, "gameinternationalization");
const PLAYER_CHOICE_DIR = path.join(OVERRIDE_ROOT, "v1", "user-localization-settings", "player-choice");
const PLAYER_CHOICE_PATH = /^\/v1\/user-localization-settings\/player-choice\/(\d+)\/?$/;
const PLAYER_CHOICE_DEFAULT = { IsPlayerChoiceEnabled: false };

function playerChoiceBody(userId) {
  for (const name of [String(userId), "0"]) {
    try {
      const f = path.join(PLAYER_CHOICE_DIR, name);
      if (fs.existsSync(f) && fs.statSync(f).isFile()) {
        const txt = fs.readFileSync(f, "utf8").trim();
        if (txt) return txt;
      }
    } catch (e) {}
  }
  return JSON.stringify(PLAYER_CHOICE_DEFAULT);
}

// Returns { body, userId } when this upstream URL is answered locally.
function localOverrideFor(targetUrl) {
  let u;
  try {
    u = new URL(targetUrl);
  } catch (e) {
    return null;
  }
  if (u.hostname.toLowerCase() !== "gameinternationalization.roblox.com") return null;
  const m = PLAYER_CHOICE_PATH.exec(u.pathname);
  if (!m) return null;
  return { body: playerChoiceBody(m[1]), userId: m[1] };
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
  ".rbxm": "application/octet-stream",
  ".rbxl": "application/octet-stream",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".gif": "image/gif",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".woff": "font/woff",
  ".woff2": "font/woff2",
  ".ttf": "font/ttf",
  ".otf": "font/otf",
  ".mp3": "audio/mpeg",
  ".ogg": "audio/ogg",
  ".webm": "video/webm",
  ".txt": "text/plain; charset=utf-8",
  ".map": "application/json; charset=utf-8",
};

const ISOLATION_HEADERS = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "credentialless",
  "Cross-Origin-Resource-Policy": "cross-origin",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};

const API_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,POST,PUT,PATCH,DELETE,OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Accept, X-CSRF-Token, Roblox-Id",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};

function requestOrigin(req) {
  return req.headers.origin || (req.headers.host ? "http://" + req.headers.host : "");
}

/* ------------------------------------------------------------------ session */

let session = { cookie: "", user: null, source: "", savedAt: 0 };
let lastEngineJoinTrace = null;

function normalizeCookie(raw) {
  let c = String(raw || "").trim().replace(/^cookie:\s*/i, "");
  if (!c) return "";
  // Accept either the cookie value copied from DevTools or a complete cookie
  // header / name=value pair. Roblox names this cookie with a leading dot, but
  // some browsers and copied snippets omit it.
  const m = c.match(/(?:^|;\s*)\.?ROBLOSECURITY=([^;]+)/i);
  if (m) return ".ROBLOSECURITY=" + m[1].trim();
  if (c.indexOf("=") === -1) return ".ROBLOSECURITY=" + c;
  return c;
}

function loadSession() {
  try {
    const raw = fs.readFileSync(SESSION_FILE, "utf8");
    const j = JSON.parse(raw);
    if (j && j.cookie) {
      const uid = j.user && Number(j.user.id);
      if (j.install !== INSTALL_ID) {
        /* Written by another machine / another copy of this project. */
        purgeSessionFile("session was created by a different install");
      } else if (uid && LEAKED_USER_IDS.has(uid)) {
        /* Publicly leaked credential — never reuse it. */
        purgeSessionFile("session belongs to a leaked account (id " + uid + ")");
      } else {
        session = {
          cookie: normalizeCookie(j.cookie),
          user: j.user || null,
          source: j.source || "saved session",
          savedAt: j.savedAt || 0,
        };
      }
    }
  } catch (e) {
    /* no saved session */
  }
  const env = normalizeCookie(process.env.RBX_COOKIE || "");
  if (env) {
    session = { cookie: env, user: null, source: "RBX_COOKIE", savedAt: Date.now() };
  }
}

function saveSession() {
  try {
    const uid = session.user && Number(session.user.id);
    if (uid && LEAKED_USER_IDS.has(uid)) {
      /* Refuse to cache a credential that is already public. */
      return;
    }
    fs.writeFileSync(
      SESSION_FILE,
      JSON.stringify(
        {
          install: INSTALL_ID,
          cookie: session.cookie,
          user: session.user,
          source: session.source,
          savedAt: session.savedAt,
        },
        null,
        2
      ),
      { mode: 0o600 }
    );
    try { fs.chmodSync(SESSION_FILE, 0o600); } catch (e) {}
  } catch (e) {
    console.warn("[auth] could not persist session:", e.message);
  }
}

function clearSession() {
  session = { cookie: "", user: null, source: "", savedAt: 0 };
  try { fs.unlinkSync(SESSION_FILE); } catch (e) {}
}

/* ------------------------------------------------------------- http helper */

function hostAllowed(hostname) {
  if (ALLOW_ANY) return true;
  const h = String(hostname || "").toLowerCase();
  return ALLOW_HOSTS.some((d) => h === d || h.endsWith("." + d));
}

function decodeBody(buf, encoding) {
  const enc = String(encoding || "").toLowerCase();
  try {
    if (enc === "gzip") return zlib.gunzipSync(buf);
    if (enc === "deflate") return zlib.inflateSync(buf);
    if (enc === "br") return zlib.brotliDecompressSync(buf);
  } catch (e) {
    return buf;
  }
  return buf;
}

function rawRequest({ method = "GET", url, headers = {}, body = null, timeout = 30000 }) {
  return new Promise((resolve, reject) => {
    let t;
    try { t = new URL(url); } catch (e) { return reject(new Error("invalid url")); }
    if (t.protocol !== "https:" && t.protocol !== "http:") return reject(new Error("bad protocol"));
    if (!hostAllowed(t.hostname)) return reject(new Error("host not allowed: " + t.hostname));

    const mod = t.protocol === "https:" ? https : http;
    const up = mod.request(
      {
        protocol: t.protocol,
        hostname: t.hostname,
        port: t.port || undefined,
        path: t.pathname + t.search,
        method,
        headers,
        timeout,
      },
      (r) => {
        const chunks = [];
        r.on("data", (c) => chunks.push(c));
        r.on("end", () => {
          const raw = Buffer.concat(chunks);
          resolve({
            status: r.statusCode || 502,
            headers: r.headers,
            raw,
            body: decodeBody(raw, r.headers["content-encoding"]),
          });
        });
        r.on("error", reject);
      }
    );
    up.on("timeout", () => { up.destroy(new Error("upstream timeout")); });
    up.on("error", reject);
    if (body) up.write(body);
    up.end();
  });
}

async function request(opts) {
  let res = await rawRequest(opts);
  adoptRobloxCookie(res, opts);
  let redirects = 0;
  while ([301, 302, 303, 307, 308].includes(res.status) && res.headers.location && redirects < 4) {
    redirects++;
    let next;
    try { next = new URL(res.headers.location, opts.url).toString(); } catch (e) { break; }
    if (!hostAllowed(new URL(next).hostname)) break;
    const method = res.status === 303 ? "GET" : opts.method || "GET";
    const redirected = Object.assign({}, opts, { url: next, method, body: method === "GET" ? null : opts.body });
    if (session.cookie && normalizeCookie(redirected.headers && (redirected.headers.Cookie || redirected.headers.cookie)) === normalizeCookie(session.cookie)) {
      redirected.headers = Object.assign({}, redirected.headers, { Cookie: session.cookie });
    }
    res = await rawRequest(redirected);
    adoptRobloxCookie(res, redirected);
  }
  return res;
}

/* Roblox may rotate .ROBLOSECURITY in Set-Cookie on an otherwise successful
   API response. Keep the local session in sync, and invalidate its CSRF cache
   when that happens. Never adopt a response cookie from another session. */
function adoptRobloxCookie(response, opts) {
  try {
    const url = new URL(opts.url);
    if (url.hostname !== "roblox.com" && !url.hostname.endsWith(".roblox.com")) return false;
    const sent = normalizeCookie(opts.headers && (opts.headers.Cookie || opts.headers.cookie));
    if (!sent || normalizeCookie(session.cookie) !== sent) return false;
    const raw = response.headers && response.headers["set-cookie"];
    const values = Array.isArray(raw) ? raw : raw ? [raw] : [];
    for (const value of values) {
      const match = String(value).match(/(?:^|[,\s])\.ROBLOSECURITY=([^;]+)/i);
      if (!match) continue;
      const rotated = normalizeCookie(".ROBLOSECURITY=" + match[1].trim());
      if (!rotated || rotated === sent) return false;
      session = Object.assign({}, session, { cookie: rotated, savedAt: Date.now() });
      csrfCache = { token: null, cookie: null, at: 0 };
      saveSession();
      console.log("[auth] stored a Roblox .ROBLOSECURITY rotation from Set-Cookie");
      return true;
    }
  } catch (e) {}
  return false;
}

function json(res, status, obj) {
  const buf = Buffer.from(JSON.stringify(obj));
  res.writeHead(status, Object.assign({ "Content-Type": "application/json; charset=utf-8", "Content-Length": buf.length }, API_HEADERS));
  res.end(buf);
}

function readJsonBody(req, limit = 1024 * 1024) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    req.on("data", (c) => {
      size += c.length;
      if (size > limit) { req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
      catch (e) { resolve({}); }
    });
    req.on("error", () => resolve({}));
  });
}

/* --------------------------------------------------------------- roblox api */

const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

async function validateCookie(cookie) {
  const c = normalizeCookie(cookie);
  if (!c) return { ok: false, error: "no cookie" };
  try {
    const r = await request({
      url: "https://users.roblox.com/v1/users/authenticated",
      headers: {
        Cookie: c,
        Accept: "application/json",
        "User-Agent": BROWSER_UA,
        "Accept-Language": "en-US,en;q=0.9",
      },
    });
    if (r.status === 200) {
      let u = null;
      try { u = JSON.parse(r.body.toString("utf8")); } catch (e) {}
      if (u && u.id) return { ok: true, user: { id: u.id, name: u.name, displayName: u.displayName || u.name } };
    }
    let msg = "Roblox rejected this session";
    try {
      const j = JSON.parse(r.body.toString("utf8"));
      if (j && j.errors && j.errors[0] && j.errors[0].message) msg = j.errors[0].message;
    } catch (e) {}
    return { ok: false, error: msg, status: r.status };
  } catch (e) {
    return { ok: false, error: "could not reach Roblox: " + e.message };
  }
}

/* ---- CSRF tokens ----------------------------------------------------------
   Roblox requires an X-CSRF-Token on every state-changing request. The usual
   dance is "send it, get 403, read the token from that 403, resend", which is
   what this server did. That works for most endpoints, but POST
   /v1/join-game answers a token-less request with HTTP 200 and
   {"status":12,"message":"Unable to join Game 211"} -- indistinguishable from
   a bad credential. So fetch a token up front for join traffic and send it on
   the first attempt.

   auth.roblox.com/v2/logout is the canonical token mint: it always answers 403
   with a fresh x-csrf-token and does not end the session.
--------------------------------------------------------------------------- */
let csrfCache = { token: null, cookie: null, at: 0 };

async function getCsrfToken(cookie, force) {
  const c = normalizeCookie(cookie);
  if (!c) return null;
  const tiedToSession = normalizeCookie(session.cookie) === c;
  const usable =
    csrfCache.token && csrfCache.cookie === c && Date.now() - csrfCache.at < 5 * 60 * 1000;
  if (usable && !force) return csrfCache.token;
  try {
    const r = await request({
      url: "https://auth.roblox.com/v2/logout",
      method: "POST",
      headers: {
        Cookie: c,
        "Content-Type": "application/json",
        Accept: "application/json",
        "User-Agent": BROWSER_UA,
        "Accept-Encoding": "identity",
      },
      body: Buffer.from("{}"),
    });
    const t = r.headers["x-csrf-token"];
    if (t) {
      // A Set-Cookie on the token response may rotate the cookie. The token
      // belongs to that same server session, so key the cache to the current
      // cookie and send that cookie alongside it on the join request.
      const tokenCookie = tiedToSession ? (normalizeCookie(session.cookie) || c) : c;
      csrfCache = { token: t, cookie: tokenCookie, at: Date.now() };
      return t;
    }
  } catch (e) {}
  return null;
}

/* Roblox documents session refresh as a way to receive a rotated
   .ROBLOSECURITY via Set-Cookie. Do this immediately before join traffic so
   the game request and its CSRF token use the same current session value. */
async function refreshRobloxSessionCookie(cookie) {
  const c = normalizeCookie(cookie);
  if (!c) return { status: 0, rotated: false };
  const usesSession = normalizeCookie(session.cookie) === c;
  const before = usesSession ? session.cookie : c;
  try {
    const opts = {
      url: "https://auth.roblox.com/v1/session/refresh",
      method: "POST",
      headers: {
        Cookie: c,
        Accept: "application/json",
        "User-Agent": BROWSER_UA,
        "Accept-Encoding": "identity",
      },
      body: null,
    };
    let r = await request(opts);
    // Like other authenticated Roblox POSTs, the refresh endpoint can first
    // return a CSRF challenge. Retry with that token and the latest cookie.
    if (r.status === 403 && r.headers["x-csrf-token"]) {
      const currentCookie = usesSession && session.cookie ? session.cookie : c;
      r = await request(Object.assign({}, opts, {
        headers: Object.assign({}, opts.headers, {
          Cookie: currentCookie,
          "X-CSRF-Token": r.headers["x-csrf-token"],
        }),
      }));
    }
    return {
      status: r.status,
      rotated: normalizeCookie(session.cookie) !== normalizeCookie(before),
    };
  } catch (e) {
    return { status: 0, rotated: false };
  }
}

async function fetchAvatar(userId) {
  try {
    const meta = await request({
      url:
        "https://thumbnails.roblox.com/v1/users/avatar-headshot?userIds=" +
        encodeURIComponent(userId) +
        "&size=150x150&format=Png&isCircular=false",
      headers: { Accept: "application/json", "User-Agent": BROWSER_UA },
    });
    const j = JSON.parse(meta.body.toString("utf8"));
    const url = j && j.data && j.data[0] && j.data[0].imageUrl;
    if (!url) return null;
    const img = await request({ url, headers: { Accept: "image/*", "User-Agent": BROWSER_UA } });
    if (img.status !== 200) return null;
    return { body: img.body, type: img.headers["content-type"] || "image/png" };
  } catch (e) {
    return null;
  }
}

/* ------------------------------------------------- browser cookie detection */

const cookieDetect = require("./lib/cookie-detect");
const cdpDetect = require("./lib/cdp-detect");

/**
 * Scan every browser profile we can see, then validate each cookie we managed
 * to decrypt against Roblox. Returns a report that is safe to show the user.
 */
async function detectFromBrowser(options) {
  options = options || {};
  const attempts = [];
  const rejected = [];
  /*
   * 1. DevTools Protocol first.
   *
   * If Chrome was started with --remote-debugging-port it will hand us the
   * already-decrypted .ROBLOSECURITY cookie. No Keychain prompt on macOS, no
   * App-Bound Encryption problem on Windows, no database parsing at all. When
   * the port is closed this fails in a few milliseconds and we fall through.
   */
  let cdp = { reports: [], candidates: [] };
  try {
    cdp = await cdpDetect.scan(options.sameBrowserOnly ? { origin: options.origin } : undefined);
  } catch (e) {
    cdp = { reports: [{ ok: false, error: e.message }], candidates: [] };
  }
  for (const r of cdp.reports) {
    attempts.push({
      method: "devtools",
      port: r.port,
      browser: r.browser,
      ok: r.ok,
      cookies: r.cookies,
      hasRobloxSession: r.hasRobloxSession,
      error: r.error,
    });
  }
  for (const cand of cdp.candidates) {
    const v = await validateCookie(cand.cookie);
    if (v.ok) {
      return {
        found: true,
        authenticated: true,
        user: v.user,
        cookie: cand.cookie,
        source: cand.source,
        browser: cand.browser,
        method: "devtools",
        attempts,
        cdpReports: cdp.reports,
      };
    }
    rejected.push({ browser: cand.browser, method: "devtools", error: v.error });
    attempts.push({ method: "devtools", port: cand.port, note: "cookie found but rejected by Roblox", error: v.error });
  }

  /*
   * 2. Cookie database on disk (Linux/Windows/macOS with Keychain allowed).
   */
  // In strict mode, search only cookie stores belonging to this browser
  // family. Never fall through to other browser apps on the device.
  const supportedBrowserFamilies = ["chrome", "edge", "brave", "opera", "vivaldi", "firefox", "safari"];
  const scan = cookieDetect.scan(options.sameBrowserOnly
    ? { browserFamily: supportedBrowserFamilies.includes(options.browserFamily) ? options.browserFamily : "unknown" }
    : undefined);
  for (const r of scan.reports) {
    attempts.push({
      method: "database",
      path: r.path,
      browser: r.browser,
      profile: r.profile,
      key: r.key,
      robloxRows: r.robloxRows,
      decrypted: r.cookies.length,
      errors: r.errors,
    });
  }

  for (const cand of scan.candidates) {
    const v = await validateCookie(cand.cookie);
    if (v.ok) {
      return {
        found: true,
        authenticated: true,
        user: v.user,
        cookie: cand.cookie,
        source: cand.source,
        path: cand.path,
        browser: cand.browser,
        method: "database",
        attempts,
        reports: scan.reports,
        cdpReports: cdp.reports,
      };
    }
    rejected.push({ path: cand.path, browser: cand.browser, method: "database", error: v.error });
    attempts.push({ path: cand.path, browser: cand.browser, method: "database", note: "cookie found but rejected by Roblox", error: v.error });
  }

  const cdpOpen = cdp.reports.filter((r) => r.ok).length;
  let hint = cookieDetect.explain(scan.reports);
  if (options.sameBrowserOnly && !scan.reports.length) {
    hint = "This browser's cookie store could not be read automatically. Try the browser access option below or paste your security cookie.";
  } else if (!options.sameBrowserOnly && cdpOpen && !cdp.candidates.length) {
    hint =
      "Connected to your browser over the DevTools Protocol, but it has no .ROBLOSECURITY cookie. " +
      "Sign in at roblox.com in that browser window, then press detect again.";
  } else if (!options.sameBrowserOnly && !cdpOpen && !scan.candidates.length) {
    hint +=
      " Faster alternative: start Chrome with --remote-debugging-port=9222 and this will read the cookie with no Keychain prompt.";
  }

  return {
    found: scan.candidates.length > 0 || cdp.candidates.length > 0,
    authenticated: false,
    attempts,
    reports: scan.reports,
    cdpReports: cdp.reports,
    rejected,
    hint,
  };
}

/* --------------------------------------------------------- session refresh

   Roblox rotates .ROBLOSECURITY. When the browser refreshes the cookie (or the
   user signs in again) the value we cached in .rbx-session.json stops working
   and every join starts failing with status 12, even though the account is
   perfectly signed in. So never trust the cache blindly: on any auth failure,
   re-read the cookie from the browser and retry once.
--------------------------------------------------------------------------- */
async function refreshSession(reason) {
  let det;
  try {
    det = await detectFromBrowser();
  } catch (e) {
    return { refreshed: false, error: e.message };
  }
  if (!det.authenticated) {
    return { refreshed: false, found: !!det.found, hint: det.hint, rejected: det.rejected };
  }
  const changed = det.cookie !== session.cookie;
  session = { cookie: det.cookie, user: det.user, source: det.source, savedAt: Date.now() };
  saveSession();
  console.log(
    `[auth] session refreshed from ${det.source}` +
      (reason ? ` (${reason})` : "") +
      (changed ? " \u2014 cookie had rotated" : " \u2014 cookie unchanged")
  );
  return { refreshed: true, changed, user: det.user, source: det.source, method: det.method };
}

/* ------------------------------------------------- fast cookie freshening

   Roblox rotates .ROBLOSECURITY constantly. Rather than waiting for a join to
   fail and then recovering, ask the browser for its *current* cookie up front.
   This only uses the DevTools Protocol, so it is a few milliseconds and never
   triggers a Keychain prompt. When Chrome is not listening it is a no-op and
   the cached cookie is used unchanged.
--------------------------------------------------------------------------- */
async function freshenSession() {
  try {
    const scan = await cdpDetect.scan();
    for (const cand of scan.candidates) {
      if (cand.cookie === session.cookie) return { changed: false, ok: true };
      const v = await validateCookie(cand.cookie);
      if (v.ok) {
        session = { cookie: cand.cookie, user: v.user, source: cand.source, savedAt: Date.now() };
        saveSession();
        console.log("[auth] picked up rotated cookie from " + cand.source);
        return { changed: true, ok: true, user: v.user };
      }
    }
  } catch (e) {}
  return { changed: false, ok: false };
}

/* ------------------------------------------------------- same-browser auto

   The whole point of this build: if the person is already signed in at
   roblox.com *in the browser they are using right now*, the app should notice
   that on its own -- no clicking, no pasting. The DevTools Protocol is the one
   channel that hands us the already-decrypted .ROBLOSECURITY cookie from that
   exact browser, so this helper is deliberately CDP-only and fast (a few ms).
   It never touches the Keychain and never blocks on a cookie-database scan.

   Returns { authenticated, user, source, port } and, on success, installs the
   session server-side so every later /api call (join, verify, proxy) can use
   it.
--------------------------------------------------------------------------- */
async function autoDetectCDP(origin) {
  let scan;
  try {
    scan = await cdpDetect.scan(origin ? { origin } : undefined);
  } catch (e) {
    return { authenticated: false, error: e.message, reports: [] };
  }
  for (const cand of scan.candidates) {
    // Reuse the cached session if the cookie has not rotated.
    if (session.cookie === cand.cookie && session.user) {
      return {
        authenticated: true,
        user: session.user,
        source: session.source || cand.source,
        port: cand.port,
        reused: true,
        reports: scan.reports,
      };
    }
    const v = await validateCookie(cand.cookie);
    if (v.ok) {
      session = { cookie: cand.cookie, user: v.user, source: cand.source, savedAt: Date.now() };
      saveSession();
      console.log("[auth] auto-detected @" + v.user.name + " from " + cand.source);
      return {
        authenticated: true,
        user: v.user,
        source: cand.source,
        port: cand.port,
        reused: false,
        reports: scan.reports,
      };
    }
  }
  return {
    authenticated: false,
    found: scan.candidates.length > 0,
    reports: scan.reports,
    hint: cdpDetect.explain(scan.reports),
  };
}

/* ------------------------------------------------------------------- proxy */

async function proxyRequest(req, res, target) {
  let t;
  try { t = new URL(target); }
  catch (e) { res.writeHead(400, { "Content-Type": "text/plain" }); return res.end("invalid target url"); }
  if (t.protocol !== "https:" && t.protocol !== "http:") {
    res.writeHead(400, { "Content-Type": "text/plain" });
    return res.end("only http(s) targets allowed");
  }
  if (!hostAllowed(t.hostname)) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    return res.end("host not allowed: " + t.hostname);
  }

  const chunks = [];
  let size = 0;
  req.on("data", (c) => {
    size += c.length;
    if (size > 20 * 1024 * 1024) { req.destroy(); return; }
    chunks.push(c);
  });
  req.on("end", async () => {
    const body = Buffer.concat(chunks);
    const headers = {};
    // Forward everything the engine sent, minus the things that must not be
    // relayed: Origin/Referer (Roblox 404s any origin it does not know — that
    // was the "HttpError: Unknown url" / 529 join failure), Cookie (the
    // server-side session always wins), and hop-by-hop headers.
    const DROP = new Set([
      "host", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
      "te", "trailer", "transfer-encoding", "upgrade", "content-length",
      "accept-encoding", "origin", "referer", "cookie", "sec-fetch-site",
      "sec-fetch-mode", "sec-fetch-dest", "sec-ch-ua", "sec-ch-ua-mobile",
      "sec-ch-ua-platform", "if-none-match", "if-modified-since",
    ]);
    for (const k of Object.keys(req.headers)) {
      if (DROP.has(k)) continue;
      headers[k] = req.headers[k];
    }
    if (!headers["user-agent"]) headers["User-Agent"] = BROWSER_UA;
    if (!headers["accept"]) headers["Accept"] = "application/json, text/plain, */*";
    headers["Accept-Encoding"] = "identity";

    /*
     * Which credential does the request travel with?
     *
     * Historically the server-side session always won, and the engine's own
     * Cookie header was dropped. That is wrong when the server has no session
     * yet: the engine still holds a perfectly good .ROBLOSECURITY (it is given
     * one through __wasmDevSettings.authCookie, which is why the console says
     * "[CookiePool] Using user-supplied cookie"), and dropping it turned an
     * authenticated join into an anonymous one. Roblox answers an anonymous
     * POST /v1/join-game with HTTP 200 and {"status":12,"message":"Unable to
     * join Game 211"}, which the engine reports as the opaque
     * "Not authorized to join this experience".
     *
     * So: prefer the server session (it is the one we have validated), but
     * fall back to whatever the engine sent. `incomingCookie` is kept so a
     * refused join can be retried with it below.
     */
    const incomingCookie = normalizeCookie(req.headers.cookie);
    let chosenCookie = session.cookie || incomingCookie;
    const joinUsesSessionCookie = !!session.cookie && normalizeCookie(chosenCookie) === normalizeCookie(session.cookie);
    if (chosenCookie) headers["Cookie"] = chosenCookie;
    if (body.length) headers["Content-Length"] = String(body.length);

    /*
     * Join traffic is the one thing that cannot be debugged from the page:
     * the request is issued inside the engine's Web Worker, so the browser
     * console only ever shows the engine's translated failure ("status 12"),
     * never the URL, body or Roblox reply. Log the round-trip here, where we
     * actually have it.
     */
    const isJoin = /gamejoin\.roblox\.com|\/v1\/join/i.test(target);
    const trace = isJoin ? {
      at: Date.now(),
      placeId: (() => {
        try { return String(JSON.parse(body.toString("utf8")).placeId || ""); } catch (e) { return ""; }
      })(),
      method: req.method,
      cookieSource: session.cookie ? "server session" : incomingCookie ? "engine request" : "none",
      cookieAttached: !!chosenCookie,
      csrfAttached: !!(headers["x-csrf-token"] || headers["X-CSRF-Token"]),
      csrfCookieAligned: null,
      retries: [],
    } : null;

    // The proxy must not forward localhost as the request origin. Roblox's
    // web join endpoint expects the same first-party context as a web launch;
    // supplying no Origin/Referer (or localhost) can be treated differently
    // from a Creator Web Play request. Keep this scoped to gamejoin only.
    if (isJoin) {
      const joinPlaceId = trace && trace.placeId;
      headers.Origin = "https://www.roblox.com";
      headers.Referer = "https://www.roblox.com/games/" + encodeURIComponent(joinPlaceId || "") + "/";
    }

    const responseSummary = (response) => {
      let data = null;
      try { data = JSON.parse(response.body.toString("utf8")); } catch (e) {}
      return {
        httpStatus: response.status,
        robloxStatus: data && typeof data.status === "number" ? data.status : null,
        message: String((data && (data.message || (data.errors && data.errors[0] && data.errors[0].message))) || "").slice(0, 180),
        joinScriptIssued: !!(data && data.joinScript),
      };
    };

    // Refresh Roblox's session cookie before joining, then mint a CSRF token
    // for that exact cookie. A token or cookie captured by the engine earlier
    // can be stale by the time its server request arrives.
    if (isJoin && req.method !== "GET" && chosenCookie) {
      if (trace) {
        const refresh = await refreshRobloxSessionCookie(chosenCookie);
        trace.sessionRefreshHttpStatus = refresh.status || null;
        trace.sessionCookieRotated = refresh.rotated;
        if (refresh.rotated && session.cookie) chosenCookie = session.cookie;
        headers.Cookie = chosenCookie;
      }
      delete headers["x-csrf-token"];
      delete headers["X-CSRF-Token"];
      const t = await getCsrfToken(chosenCookie, true);
      if (t) headers["X-CSRF-Token"] = t;
      if (joinUsesSessionCookie && session.cookie) chosenCookie = session.cookie;
      headers.Cookie = chosenCookie;
      trace.csrfCookieAligned = !!t && csrfCache.cookie === normalizeCookie(chosenCookie);
    }

    if (isJoin) {
      trace.csrfAttached = !!(headers["x-csrf-token"] || headers["X-CSRF-Token"]);
      console.log(
        `[join] -> ${req.method} ${target} body=${body.length ? body.toString("utf8").slice(0, 400) : "(none)"}` +
          ` cookie=${session.cookie ? "session(" + session.cookie.length + "b)" : incomingCookie ? "engine(" + incomingCookie.length + "b)" : "NONE"}` +
          ` csrf=${headers["x-csrf-token"] || headers["X-CSRF-Token"] ? "yes" : "no"}`
      );
    }

    const send = async (extra) => {
      const h = Object.assign({}, headers, extra || {});
      return request({ url: target, method: req.method, headers: h, body: body.length ? body : null });
    };

    try {
      let r = await send();
      // Roblox CSRF: a 403 carries a fresh token; retry once with it.
      if (r.status === 403 && r.headers["x-csrf-token"]) {
        if (joinUsesSessionCookie && session.cookie) chosenCookie = session.cookie;
        headers.Cookie = chosenCookie;
        csrfCache = { token: r.headers["x-csrf-token"], cookie: normalizeCookie(chosenCookie), at: Date.now() };
        r = await send({ "X-CSRF-Token": r.headers["x-csrf-token"] });
      }
      if (isJoin) {
        trace.initial = responseSummary(r);
        console.log(
          `[join] <- ${r.status} ${r.headers["content-type"] || ""} ` +
            r.body.toString("utf8").slice(0, 600).replace(/\s+/g, " ")
        );
      }

      /*
       * Self-heal a refused join.
       *
       * status 12 is Roblox's "I did not accept that credential" answer to
       * POST /v1/join-game (verified: an unauthenticated join returns exactly
       * {"status":12,"message":"Unable to join Game 211"}). Two things cause it
       * here:
       *
       *   1. the request went out with no cookie at all. The engine cannot
       *      send one -- Cookie is a forbidden header on XMLHttpRequest, so the
       *      browser strips it and the proxy is the only path a credential can
       *      take;
       *   2. the cached cookie rotated while the engine was booting. Roblox
       *      rotates .ROBLOSECURITY on ordinary API calls, and the engine
       *      spends about a minute loading before it joins.
       *
       * So: if the engine brought a cookie, try that; otherwise ask the
       * browser for its current cookie over CDP and try that. Adopt whichever
       * Roblox accepts so every later call agrees with it.
       */
      if (isJoin && r.status === 200) {
        let d = null;
        try { d = JSON.parse(r.body.toString("utf8")); } catch (e) {}
        if (d && d.status === 12) {
          const candidates = [];
          const addCandidate = (label, cookie) => {
            if (cookie && !candidates.some((candidate) => candidate[1] === cookie)) {
              candidates.push([label, cookie]);
            }
          };
          if (incomingCookie && incomingCookie !== chosenCookie) addCandidate("engine", incomingCookie);
          const before = session.cookie;
          try {
            const fresh = await freshenSession();
            trace.devToolsRefreshChanged = !!(fresh && fresh.changed);
            if (fresh && fresh.changed && session.cookie && session.cookie !== before) {
              addCandidate("DevTools", session.cookie);
            }
          } catch (e) {}
          // The engine may take a while to download the WebClient before it
          // asks to join. Its captured cookie can rotate during that time, and
          // many browsers are not running with DevTools enabled. If the fast
          // DevTools refresh did not supply a retry credential, use the same
          // browser-cookie detector as the login screen and retry with the
          // session it validates.
          try {
            const refreshed = await refreshSession("engine join returned status 12");
            trace.browserRefreshSucceeded = !!(refreshed && refreshed.refreshed);
            if (refreshed && refreshed.refreshed && session.cookie) {
              addCandidate("browser", session.cookie);
            }
          } catch (e) {}

          for (const cand of candidates) {
            const label = cand[0];
            const cookie = cand[1];
            console.log("[join] status 12; retrying with the " + label + " cookie");
            const alt = Object.assign({}, headers, { Cookie: cookie });
            // A CSRF token is session-specific. A token minted for the old
            // cookie can make a refreshed, otherwise-valid session look like
            // another status-12 refusal, so mint one for each retry cookie.
            delete alt["x-csrf-token"];
            delete alt["X-CSRF-Token"];
            const retryUsesSessionCookie = normalizeCookie(cookie) === normalizeCookie(session.cookie);
            const retryCsrf = await getCsrfToken(cookie, true);
            if (retryCsrf) alt["X-CSRF-Token"] = retryCsrf;
            if (retryUsesSessionCookie && session.cookie) alt.Cookie = session.cookie;
            let r2 = await request({ url: target, method: req.method, headers: alt, body: body.length ? body : null });
            if (r2.status === 403 && r2.headers["x-csrf-token"]) {
              if (retryUsesSessionCookie && session.cookie) alt.Cookie = session.cookie;
              r2 = await request({
                url: target,
                method: req.method,
                headers: Object.assign({}, alt, { Cookie: alt.Cookie || cookie, "X-CSRF-Token": r2.headers["x-csrf-token"] }),
                body: body.length ? body : null,
              });
            }
            let d2 = null;
            try { d2 = JSON.parse(r2.body.toString("utf8")); } catch (e) {}
            trace.retries.push({
              cookieSource: label,
              csrfAttached: !!retryCsrf,
              csrfCookieAligned: !retryUsesSessionCookie || csrfCache.cookie === normalizeCookie(alt.Cookie || cookie),
              response: responseSummary(r2),
            });
            if (d2 && typeof d2.status === "number" && d2.status !== 12) {
              r = r2;
              session.cookie = cookie;
              session.source = label + " cookie (adopted on join)";
              saveSession();
              console.log("[join] " + label + " cookie accepted; adopted into server session");
              break;
            }
            console.log("[join] " + label + " cookie also refused: " + ((d2 && d2.message) || "no message"));
          }
        }
      }

      // A single delayed retry covers a transient server-allocation race
      // after the engine has entered its waiting state. Keep it bounded and
      // use the current session plus a token minted for that session.
      if (isJoin && r.status === 200) {
        let current = null;
        try { current = JSON.parse(r.body.toString("utf8")); } catch (e) {}
        if (current && current.status === 12) {
          await new Promise((resolve) => setTimeout(resolve, 20000));
          const retryUsesSessionCookie = !!session.cookie;
          let retryCookie = session.cookie || chosenCookie;
          const delayedHeaders = Object.assign({}, headers);
          delete delayedHeaders["x-csrf-token"];
          delete delayedHeaders["X-CSRF-Token"];
          const delayedCsrf = await getCsrfToken(retryCookie, true);
          if (retryUsesSessionCookie && session.cookie) retryCookie = session.cookie;
          if (retryCookie) delayedHeaders.Cookie = retryCookie;
          if (delayedCsrf) delayedHeaders["X-CSRF-Token"] = delayedCsrf;
          let delayed = await request({
            url: target,
            method: req.method,
            headers: delayedHeaders,
            body: body.length ? body : null,
          });
          if (delayed.status === 403 && delayed.headers["x-csrf-token"]) {
            if (retryUsesSessionCookie && session.cookie) retryCookie = session.cookie;
            delayedHeaders.Cookie = retryCookie;
            delayedHeaders["X-CSRF-Token"] = delayed.headers["x-csrf-token"];
            delayed = await request({
              url: target,
              method: req.method,
              headers: delayedHeaders,
              body: body.length ? body : null,
            });
          }
          let delayedData = null;
          try { delayedData = JSON.parse(delayed.body.toString("utf8")); } catch (e) {}
          trace.retries.push({
            cookieSource: "delayed current-session retry",
            delayMs: 20000,
            csrfAttached: !!delayedCsrf,
            csrfCookieAligned: !retryUsesSessionCookie || csrfCache.cookie === normalizeCookie(retryCookie),
            response: responseSummary(delayed),
          });
          if (delayedData && typeof delayedData.status === "number" && delayedData.status !== 12) {
            r = delayed;
          }
        }
      }

      const out = {};
      if (isJoin) {
        trace.final = responseSummary(r);
        trace.completedAt = Date.now();
        lastEngineJoinTrace = trace;
      }
      for (const k of [
        "content-type",
        "cache-control",
        "etag",
        "last-modified",
        "x-csrf-token",
        "content-disposition",
        "accept-ranges",
        "content-range",
      ]) {
        if (r.headers[k]) out[k] = r.headers[k];
      }
      // Body is already decompressed by request(); never advertise an encoding.
      out["Content-Length"] = String(r.body.length);
      Object.assign(out, API_HEADERS);
      res.writeHead(r.status, out);
      res.end(r.body);
    } catch (e) {
      if (trace) {
        trace.error = String(e && e.message || e).slice(0, 180);
        trace.completedAt = Date.now();
        lastEngineJoinTrace = trace;
      }
      if (!res.headersSent) {
        res.writeHead(502, Object.assign({ "Content-Type": "application/json; charset=utf-8" }, API_HEADERS));
      }
      res.end(JSON.stringify({ error: "proxy failure", message: e.message }));
    }
  });
}

/* -------------------------------------------------------------- html inject */

function injectSession(html) {
  const payload = {
    authenticated: !!(session.cookie && session.user),
    user: session.user || null,
    cookie: session.cookie || "",
    source: session.source || "",
  };
  const tag =
    "<script>window.__RBX_SESSION=" +
    JSON.stringify(payload).replace(/</g, "\\u003c") +
    ";</script>";
  if (html.indexOf("<!--RBX_SESSION-->") !== -1) return html.replace("<!--RBX_SESSION-->", tag);
  const i = html.indexOf("<script");
  if (i === -1) return html.replace("</head>", tag + "</head>");
  return html.slice(0, i) + tag + "\n" + html.slice(i);
}

/* -------------------------------------------------------------------- server */

/* Cached WebClient engine version (see /api/engine-version). */
let engineVersionCache = null;

const server = http.createServer((req, res) => {
  let parsed;
  try { parsed = new URL(req.url, "http://localhost"); }
  catch (e) { res.writeHead(400); return res.end("bad url"); }

  const p = parsed.pathname;

  if (req.method === "OPTIONS" && p.startsWith("/api/")) {
    res.writeHead(204, API_HEADERS);
    return res.end();
  }

  /* ---- proxy ---- */
  if (p === "/api/p" || p === "/p") {
    const target = parsed.searchParams.get("url");
    if (!target) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      return res.end("missing ?url=");
    }
    // Answered from disk: never leave the machine.
    const override = localOverrideFor(target);
    if (override) {
      console.log(`[override] ${target} -> local (user ${override.userId})`);
      return json(res, 200, JSON.parse(override.body));
    }
    return proxyRequest(req, res, target);
  }

  /* ---- local override, served same-origin (no proxy needed) ---- */
  {
    const m = /^\/gameinternationalization\/v1\/user-localization-settings\/player-choice\/(\d+)\/?$/.exec(p);
    if (m) {
      const body = playerChoiceBody(m[1]);
      res.writeHead(200, Object.assign({
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "Access-Control-Allow-Origin": "*",
      }, ISOLATION_HEADERS));
      return res.end(req.method === "HEAD" ? undefined : body);
    }
  }

  /* ---- health ---- */
  /* ---- download the packaged build ---- */
  if (p === "/download" || p === "/download/robloxweb.zip") {
    const zipName = "RobloxWeb-modded.zip";
    const zipPath = [
      path.join(ROOT, zipName),
      path.join(ROOT, "..", zipName),
      path.join(ROOT, "..", "..", zipName),
    ].find((f) => { try { return fs.statSync(f).isFile(); } catch (e) { return false; } });
    let st;
    try {
      st = fs.statSync(zipPath);
    } catch (e) {
      return json(res, 404, { error: "zip not found next to the build" });
    }
    res.writeHead(200, {
      "Content-Type": "application/zip",
      "Content-Length": st.size,
      "Content-Disposition": 'attachment; filename="RobloxWeb-modded.zip"',
      "Cache-Control": "no-store",
    });
    if (req.method === "HEAD") return res.end();
    return fs.createReadStream(zipPath).pipe(res);
  }

  /* ---- live WebClient engine version --------------------------------------
     WasmLoader.js resolves this itself from clientsettings.roblox.com, but
     that call is cross-origin and CORS-blocked from the browser, so it falls
     back to the version the /games/start chunk seeded into localStorage —
     which is baked into the build and goes stale (the CDN then answers 403
     and the engine never boots). Answering it here lets client.html pin the
     current version before WasmLoader runs. */
  if (p === "/api/engine-version") {
    const cached = engineVersionCache;
    const fresh = cached && Date.now() - cached.at < 5 * 60 * 1000;
    const reply = (v) => json(res, 200, v);
    if (fresh) return reply(cached.value);
    return request({
      url: "https://clientsettings.roblox.com/v2/client-version/WebClientApp",
      method: "GET",
      headers: { Accept: "application/json", "User-Agent": BROWSER_UA },
    })
      .then((r) => {
        let data = {};
        try { data = JSON.parse(r.body.toString("utf8")); } catch (e) {}
        if (!data.clientVersionUpload) throw new Error("no clientVersionUpload in response");
        engineVersionCache = { at: Date.now(), value: data };
        reply(data);
      })
      .catch((e) => {
        // Serve a stale value rather than nothing: the page can still try.
        if (cached) return reply(cached.value);
        json(res, 502, { error: "engine version lookup failed", message: e.message });
      });
    return;
  }

  if (p === "/api/health" || p === "/health") {
    return json(res, 200, {
      ok: true,
      buildId: BUILD_ID,
      root: ROOT,
      pid: process.pid,
      cookie: !!session.cookie,
      authenticated: !!(session.cookie && session.user),
      user: session.user,
      allow: ALLOW_HOSTS,
      node: process.version,
      platform: process.platform,
      keychainAllowed: cookieDetect.keychainAllowed,
      cdpPorts: cdpDetect.ports(),
    });
  }

  /* ---- auth ---- */
  if (p === "/api/auth/status") {
    (async () => {
      const sameBrowserOnly = parsed.searchParams.get("sameBrowserOnly") === "1";
      if (sameBrowserOnly) {
        const auto = await autoDetectCDP(requestOrigin(req));
        if (auto.authenticated) {
          return json(res, 200, {
            authenticated: true,
            user: auto.user,
            source: auto.source,
            auto: true,
            avatar: "/api/avatar?userId=" + encodeURIComponent(auto.user.id),
          });
        }
        return json(res, 200, {
          authenticated: false,
          user: null,
          source: "",
          hint: "This browser could not be checked directly. Start it with the DevTools port enabled, or turn on device-wide detection.",
        });
      }
      // Same-browser auto sign-in: if we have no cached session, ask the
      // browser we are being viewed in (over CDP) who is signed in at
      // roblox.com right now. This is what makes the app "just work" when the
      // user is already logged in on this machine.
      if (!session.cookie) {
        const auto = await autoDetectCDP(requestOrigin(req));
        if (auto.authenticated) {
          return json(res, 200, {
            authenticated: true,
            user: auto.user,
            source: auto.source,
            auto: true,
            avatar: "/api/avatar?userId=" + encodeURIComponent(auto.user.id),
          });
        }
        return json(res, 200, { authenticated: false, user: null, source: "", hint: auto.hint });
      }
      if (!session.user || parsed.searchParams.get("refresh")) {
        const v = await validateCookie(session.cookie);
        if (!v.ok) {
          clearSession();
          return json(res, 200, { authenticated: false, user: null, source: "", error: v.error });
        }
        session.user = v.user;
        saveSession();
      }
      return json(res, 200, {
        authenticated: true,
        user: session.user,
        source: session.source,
        avatar: "/api/avatar?userId=" + encodeURIComponent(session.user.id),
      });
    })();
    return;
  }

  if (p === "/api/auth/keychain" && req.method === "POST") {
    // Explicit opt-in to the macOS Keychain dialog. Only called when the user
    // presses the button, so no system prompt ever appears unprompted.
    (async () => {
      const options = await readJsonBody(req);
      cookieDetect.allowKeychain();
      const sameBrowserOnly = options.sameBrowserOnly === true;
      const det = await detectFromBrowser({
        sameBrowserOnly,
        origin: sameBrowserOnly ? requestOrigin(req) : "",
        browserFamily: options.browserFamily,
      });
      if (det.authenticated) {
        session = { cookie: det.cookie, user: det.user, source: det.source, savedAt: Date.now() };
        saveSession();
        return json(res, 200, {
          authenticated: true,
          user: session.user,
          source: session.source,
          path: det.path,
          avatar: "/api/avatar?userId=" + encodeURIComponent(session.user.id),
        });
      }
      return json(res, 200, {
        authenticated: false,
        found: det.found,
        hint: det.hint,
        attempts: det.attempts,
        error: det.found
          ? "A cookie was found but Roblox rejected it."
          : "Keychain access was granted, but no .ROBLOSECURITY cookie was found in the profiles that were readable.",
      });
    })();
    return;
  }

  if (p === "/api/auth/cdp" && req.method === "POST") {
    // Read the cookie straight from a running browser over the DevTools
    // Protocol. No Keychain prompt, no database decryption, no password.
    (async () => {
      let scan;
      try {
        scan = await cdpDetect.scan();
      } catch (e) {
        return json(res, 200, { authenticated: false, found: false, error: e.message });
      }
      for (const cand of scan.candidates) {
        const v = await validateCookie(cand.cookie);
        if (v.ok) {
          session = { cookie: cand.cookie, user: v.user, source: cand.source, savedAt: Date.now() };
          saveSession();
          return json(res, 200, {
            authenticated: true,
            user: session.user,
            source: session.source,
            browser: cand.browser,
            port: cand.port,
            avatar: "/api/avatar?userId=" + encodeURIComponent(session.user.id),
            reports: scan.reports,
          });
        }
      }
      return json(res, 200, {
        authenticated: false,
        found: scan.candidates.length > 0,
        hint: cdpDetect.explain(scan.reports),
        reports: scan.reports,
        error: scan.candidates.length
          ? "A cookie was found but Roblox rejected it."
          : cdpDetect.explain(scan.reports),
      });
    })();
    return;
  }

  if (p === "/api/auth/refresh" && req.method === "POST") {
    (async () => {
      const r = await refreshSession("manual refresh");
      if (!r.refreshed) {
        return json(res, 200, {
          ok: false,
          authenticated: false,
          found: !!r.found,
          hint: r.hint || r.error || "No browser session could be read.",
          rejected: r.rejected || [],
        });
      }
      return json(res, 200, {
        ok: true,
        authenticated: true,
        changed: r.changed,
        user: r.user,
        source: r.source,
        method: r.method,
        avatar: "/api/avatar?userId=" + encodeURIComponent(r.user.id),
      });
    })();
    return;
  }

  if (p === "/api/auth/diagnose") {
    // Read-only report: what profiles exist, how they are encrypted, and why a
    // cookie could not be read. No cookie value is ever returned here.
    (async () => {
      const sameBrowserOnly = parsed.searchParams.get("sameBrowserOnly") === "1";
      const browserFamily = parsed.searchParams.get("browserFamily") || "";
      const scanOptions = sameBrowserOnly && ["chrome", "edge", "brave", "opera", "vivaldi", "firefox", "safari"].includes(browserFamily)
        ? { browserFamily }
        : undefined;
      const scan = cookieDetect.scan(scanOptions);
      const profiles = cookieDetect.chromiumProfiles(scanOptions);
      return json(res, 200, {
        platform: cookieDetect.platform,
        node: process.version,
        home: os.homedir(),
        profiles: profiles.map((p) => ({
          browser: p.browser,
          dir: p.dir,
          explicit: p.explicit,
          exists: fs.existsSync(p.dir),
          key: cookieDetect.cookieKeyFor(p.dir, p.browser).note,
        })),
        databases: scan.reports.map((r) => ({
          browser: r.browser,
          path: r.path,
          exists: r.exists,
          size: r.stat ? r.stat.size : null,
          modified: r.stat ? r.stat.mtime : null,
          key: r.key,
          robloxRows: r.robloxRows,
          decrypted: r.cookies.length,
          appBound: !!r.appBound,
          errors: r.errors,
        })),
        candidates: scan.candidates.length,
        keychainAllowed: cookieDetect.keychainAllowed(),
        hint: cookieDetect.explain(scan.reports),
      });
    })();
    return;
  }

  if (p === "/api/auth/auto" && req.method === "POST") {
    // Fast same-browser check: read the live .ROBLOSECURITY straight from the
    // browser over CDP and validate it with the real Roblox endpoint. No
    // prompts, no database decryption, no pasting.
    (async () => {
      const auto = await autoDetectCDP(requestOrigin(req));
      if (auto.authenticated) {
        return json(res, 200, {
          authenticated: true,
          user: auto.user,
          source: auto.source,
          port: auto.port,
          reused: !!auto.reused,
          avatar: "/api/avatar?userId=" + encodeURIComponent(auto.user.id),
        });
      }
      return json(res, 200, {
        authenticated: false,
        found: !!auto.found,
        hint: auto.hint,
        error: auto.hint || "No signed-in Roblox session was found in this browser.",
      });
    })();
    return;
  }

  if (p === "/api/auth/detect" && req.method === "POST") {
    (async () => {
      const options = await readJsonBody(req);
      const sameBrowserOnly = options.sameBrowserOnly === true;
      const det = await detectFromBrowser({
        sameBrowserOnly,
        origin: sameBrowserOnly ? requestOrigin(req) : "",
        browserFamily: options.browserFamily,
      });
      if (det.authenticated) {
        session = { cookie: det.cookie, user: det.user, source: det.source, savedAt: Date.now() };
        saveSession();
        return json(res, 200, {
          authenticated: true,
          user: session.user,
          source: session.source,
          path: det.path,
          avatar: "/api/avatar?userId=" + encodeURIComponent(session.user.id),
          attempts: det.attempts,
        });
      }
      const notSignedIn = sameBrowserOnly
        ? "Couldn't find a usable Roblox login in this browser. Sign in to roblox.com here, allow access to this browser's cookie store if prompted, or paste your security cookie below."
        : "You're not logged into a Roblox account in the detected browser profiles. Sign in at roblox.com, or use the cookie option below.";
      return json(res, 200, {
        authenticated: false,
        found: det.found,
        attempts: det.attempts,
        rejected: det.rejected,
        hint: det.hint,
        platform: cookieDetect.platform,
        error: det.found
          ? "A Roblox cookie was found, but Roblox rejected it (it may have expired). Sign in again at roblox.com."
          : notSignedIn + (det.hint ? " " + det.hint : ""),
      });
    })();
    return;
  }

  if (p === "/api/auth/login" && req.method === "POST") {
    (async () => {
      const body = await readJsonBody(req);
      const cookie = normalizeCookie(body.cookie || "");
      if (!cookie) return json(res, 400, { authenticated: false, error: "Paste a .ROBLOSECURITY value first." });
      const v = await validateCookie(cookie);
      if (!v.ok) return json(res, 401, { authenticated: false, error: v.error || "Invalid session." });
      session = { cookie, user: v.user, source: "pasted cookie", savedAt: Date.now() };
      saveSession();
      return json(res, 200, {
        authenticated: true,
        user: session.user,
        source: session.source,
        avatar: "/api/avatar?userId=" + encodeURIComponent(session.user.id),
      });
    })();
    return;
  }

  if (p === "/api/auth/logout" && req.method === "POST") {
    clearSession();
    return json(res, 200, { authenticated: false });
  }

  /* ---- avatar proxy (COEP-safe) ---- */
  if (p === "/api/avatar") {
    const userId = parsed.searchParams.get("userId");
    if (!userId || !/^\d+$/.test(userId)) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      return res.end("bad userId");
    }
    (async () => {
      const img = await fetchAvatar(userId);
      if (!img) {
        res.writeHead(404, { "Content-Type": "text/plain" });
        return res.end("no avatar");
      }
      res.writeHead(200, {
        "Content-Type": img.type,
        "Content-Length": img.body.length,
        "Cache-Control": "public, max-age=300",
        "Cross-Origin-Resource-Policy": "cross-origin",
      });
      res.end(img.body);
    })();
    return;
  }

  /* ---- join authorization probe ---- */
  if (p === "/api/auth/verify" && req.method === "POST") {
    // Deep identity check: prove that Roblox itself knows who this session is,
    // and that the session can actually be used for joining. This is what the
    // launcher calls before booting the engine, so a missing/expired session is
    // reported as "Roblox does not recognise you" instead of a bare 524.
    (async () => {
      const body = await readJsonBody(req).catch(() => ({}));
      const placeId = String(body.placeId || "").trim();

      // Use the browser's live cookie if it has rotated since we cached it.
      await freshenSession();
      // No cached session at all? Try the same-browser CDP detection before
      // declaring the user signed out.
      if (!session.cookie) await autoDetectCDP();

      if (!session.cookie) {
        return json(res, 200, {
          ok: false,
          authenticated: false,
          code: "NO_SESSION",
          error: "No Roblox session on this server. Sign in first.",
          remedy: "Use the login screen: either continue with the browser session or paste a .ROBLOSECURITY cookie.",
        });
      }

      // 1. Who does Roblox think this is?
      const v = await validateCookie(session.cookie);
      if (!v.ok) {
        return json(res, 200, {
          ok: false,
          authenticated: false,
          code: "REJECTED",
          error: "Roblox rejected this session: " + (v.error || "not authenticated"),
          remedy: "The cookie has expired or was revoked. Sign in at roblox.com again and re-detect.",
        });
      }

      // 2. Keep the cached user in sync with what Roblox just told us.
      session.user = v.user;
      saveSession();

      const identity = {
        id: v.user.id,
        name: v.user.name,
        displayName: v.user.displayName,
        profileUrl: "https://www.roblox.com/users/" + v.user.id + "/profile",
        avatar: "/api/avatar?userId=" + encodeURIComponent(v.user.id),
      };

      // 3. Optionally prove the session can be used for a specific place.
      let place = null;
      if (/^\d+$/.test(placeId)) {
        try {
          const uni = await request({
            url: "https://apis.roblox.com/universes/v1/places/" + placeId + "/universe",
            headers: { "User-Agent": BROWSER_UA, Accept: "application/json" },
          });
          let universeId = null;
          try { universeId = JSON.parse(uni.body.toString("utf8")).universeId; } catch (e) {}

          place = { placeId: Number(placeId), universeId };

          if (universeId) {
            const det = await request({
              url: "https://games.roblox.com/v1/games?universeIds=" + universeId,
              headers: { "User-Agent": BROWSER_UA, Accept: "application/json" },
            });
            let g = null;
            try { g = JSON.parse(det.body.toString("utf8")).data[0]; } catch (e) {}
            if (g) {
              place.name = g.name;
              place.creator = g.creator;
              place.maxPlayers = g.maxPlayers;
              place.playing = g.playing;
              place.isContentRestricted = g.isContentRestricted;
              place.ownedByYou = !!(g.creator && g.creator.id === identity.id);
            }
          }

          // 4. Ask gamejoin whether this account may join, without consuming a
          //    server slot: join-game-metadata is the lightweight preflight.
          const meta = await request({
            url: "https://gamejoin.roblox.com/v1/join-game-metadata",
            method: "POST",
            headers: {
              Cookie: session.cookie,
              "Content-Type": "application/json",
              Accept: "application/json",
              "User-Agent": BROWSER_UA,
            },
            body: Buffer.from(JSON.stringify({ placeId: Number(placeId) })),
          });
          let m = null;
          try { m = JSON.parse(meta.body.toString("utf8")); } catch (e) {}
          place.preflight = {
            status: meta.status,
            message: (m && (m.message || (m.errors && m.errors[0] && m.errors[0].message))) || null,
            playabilityStatus: (m && m.playabilityStatus) || null,
            // Roblox retired this endpoint: it now answers 404 with an empty
            // error object. Say so instead of pretending the check ran, so the
            // page knows "unknown" means "not checked", not "playable".
            unavailable: meta.status === 404,
          };
        } catch (e) {
          place = { placeId: Number(placeId), error: e.message };
        }
      }

      return json(res, 200, {
        ok: true,
        authenticated: true,
        identity,
        place,
        source: session.source,
        verifiedAt: new Date().toISOString(),
      });
    })();
    return;
  }

  if (p === "/api/join" && req.method === "POST") {
    (async () => {
      const body = await readJsonBody(req);
      const placeId = String(body.placeId || "").trim();
      if (!/^\d+$/.test(placeId)) return json(res, 400, { ok: false, error: "placeId must be numeric" });

      // Always prefer the browser's current cookie over the cached one.
      await freshenSession();
      // Still nothing? Read the live session from this browser before giving up.
      if (!session.cookie) await autoDetectCDP();

      if (!session.cookie) {
        return json(res, 401, {
          ok: false,
          code: "NO_SESSION",
          error: "Not signed in. Roblox cannot know who you are without a .ROBLOSECURITY session.",
        });
      }
      const payload = Buffer.from(JSON.stringify({ placeId: Number(placeId), isTeleport: false }));
      const buildHeaders = (cookie) => ({
        Cookie: cookie,
        "Content-Type": "application/json",
        Accept: "application/json",
        "User-Agent": BROWSER_UA,
        "Accept-Encoding": "identity",
        "Content-Length": String(payload.length),
      });
      let baseHeaders = buildHeaders(session.cookie);
      // Send a CSRF token on the first attempt: join-game reports a missing
      // token as status 12, not as a 403, so the retry path never fires.
      const preToken = await getCsrfToken(session.cookie);
      if (preToken) baseHeaders["X-CSRF-Token"] = preToken;
      try {
        let r = await request({
          url: "https://gamejoin.roblox.com/v1/join-game",
          method: "POST",
          headers: baseHeaders,
          body: payload,
        });
        if (r.status === 403 && r.headers["x-csrf-token"]) {
          r = await request({
            url: "https://gamejoin.roblox.com/v1/join-game",
            method: "POST",
            headers: Object.assign({}, baseHeaders, { "X-CSRF-Token": r.headers["x-csrf-token"] }),
            body: payload,
          });
        }
        let data = null;
        try { data = JSON.parse(r.body.toString("utf8")); } catch (e) {}
        let message =
          (data && (data.message || (data.errors && data.errors[0] && data.errors[0].message))) ||
          (r.status === 200 ? "Authorized" : "Roblox refused the join");
        let authorized = r.status === 200 && !!(data && data.joinScript);

        /*
         * The cached cookie may have been rotated by the browser. If Roblox
         * refused on auth grounds, pull a fresh cookie from the browser and try
         * exactly once more. This is what turns a permanent "status 12" into a
         * working join without the user having to press anything.
         */
        let refreshed = null;
        const authRefused =
          !authorized &&
          (r.status === 401 ||
            (data && data.status === 12) ||
            /not authenticated|not authoriz|unable to join game/i.test(String(message)));
        if (authRefused) {
          refreshed = await refreshSession("join refused with status " + (data && data.status));
          if (refreshed.refreshed) {
            baseHeaders = buildHeaders(session.cookie);
            r = await request({
              url: "https://gamejoin.roblox.com/v1/join-game",
              method: "POST",
              headers: baseHeaders,
              body: payload,
            });
            if (r.status === 403 && r.headers["x-csrf-token"]) {
              r = await request({
                url: "https://gamejoin.roblox.com/v1/join-game",
                method: "POST",
                headers: Object.assign({}, baseHeaders, { "X-CSRF-Token": r.headers["x-csrf-token"] }),
                body: payload,
              });
            }
            data = null;
            try { data = JSON.parse(r.body.toString("utf8")); } catch (e) {}
            message =
              (data && (data.message || (data.errors && data.errors[0] && data.errors[0].message))) ||
              (r.status === 200 ? "Authorized" : "Roblox refused the join");
            authorized = r.status === 200 && !!(data && data.joinScript);
          }
        }

        // Roblox answers 200 with a numeric `status` even when it refuses, so a
        // bare HTTP code is meaningless. Translate it into something a human can
        // act on: status 12 is the auth failure that used to surface as the
        // opaque "Unable to join Game 211".
        let code = authorized ? "JOIN_OK" : "JOIN_REFUSED";
        let remedy = "";
        if (!authorized) {
          const m = String(message).toLowerCase();
          const st = data && typeof data.status === "number" ? data.status : null;
          if (st === 12 || /unable to join game|not authoriz|not authenticated|authentication/i.test(m)) {
            code = "NOT_AUTHORIZED";
            remedy = "Sign in again on the login screen so the cookie is fresh.";
          } else if (/full|queue/i.test(m)) {
            code = "GAME_FULL";
            remedy = "Try again in a moment.";
          } else if (/restricted|not allowed|privacy|age|verif/i.test(m)) {
            code = "RESTRICTED";
            remedy = "Check the experience\u2019s privacy setting, or your account\u2019s age/region restrictions.";
          } else if (/not found|does not exist|invalid place/i.test(m)) {
            code = "NOT_FOUND";
            remedy = "Check the place ID or the game link.";
          } else if (st === 0 && r.status !== 200) {
            code = "ROBLOX_ERROR";
            remedy = "Retry, or check status.roblox.com.";
          }
        }

        return json(res, 200, {
          ok: authorized,
          code,
          remedy,
          status: r.status,
          robloxStatus: data && typeof data.status === "number" ? data.status : null,
          message,
          refreshed: refreshed
            ? { attempted: true, ok: !!refreshed.refreshed, changed: !!refreshed.changed, hint: refreshed.hint }
            : { attempted: false },
          data,
        });
      } catch (e) {
        return json(res, 502, { ok: false, error: e.message });
      }
    })();
    return;
  }

  /* ---- why did the join fail? -------------------------------------------
     The engine collapses every refusal into "Not authorized to join this
     experience" plus a numeric status, which tells the user nothing. This
     endpoint re-runs the same checks server-side and returns a verdict the
     loading screen can print: who Roblox thinks you are, whether the place is
     playable, and what gamejoin says about *this* account.

     It deliberately uses join-game-metadata rather than join-game: metadata
     answers the same authorization question without allocating a server slot.
  ------------------------------------------------------------------------- */
  if (p === "/api/join/diagnose") {
    (async () => {
      const body = req.method === "POST" ? await readJsonBody(req).catch(() => ({})) : {};
      const placeId = String(body.placeId || parsed.searchParams.get("placeId") || "").trim();

      await freshenSession();
      if (!session.cookie) await autoDetectCDP();
      if (!session.cookie) {
        return json(res, 200, {
          ok: false,
          verdict: "NO_SESSION",
          error: "No Roblox session is attached to this server.",
          remedy: "Sign in on the login screen, then launch the experience again.",
        });
      }

      const v = await validateCookie(session.cookie);
      if (!v.ok) {
        return json(res, 200, {
          ok: false,
          verdict: "COOKIE_INVALID",
          error: "Roblox rejected the stored session: " + (v.error || "not authenticated"),
          remedy: "The .ROBLOSECURITY cookie has expired or was revoked. Sign in at roblox.com again and re-detect.",
        });
      }

      const out = {
        ok: true,
        verdict: "OK",
        identity: { id: v.user.id, name: v.user.name, displayName: v.user.displayName },
        place: { placeId: Number(placeId) || null },
      };
      if (
        lastEngineJoinTrace &&
        lastEngineJoinTrace.placeId === placeId &&
        Date.now() - lastEngineJoinTrace.at < 3 * 60 * 1000
      ) {
        // This trace contains only booleans, HTTP/status codes, and Roblox's
        // short error message. It never includes cookies, CSRF tokens, or join
        // tickets, so the on-page diagnosis is safe to share.
        out.engineRequest = lastEngineJoinTrace;
      }

      if (!/^\d+$/.test(placeId)) {
        out.verdict = "BAD_PLACE_ID";
        out.remedy = "The URL needs a numeric placeId, e.g. ?placeId=17261351778.";
        return json(res, 200, out);
      }

      try {
        const uni = await request({
          url: "https://apis.roblox.com/universes/v1/places/" + placeId + "/universe",
          headers: { "User-Agent": BROWSER_UA, Accept: "application/json" },
        });
        try { out.place.universeId = JSON.parse(uni.body.toString("utf8")).universeId || null; } catch (e) {}

        if (out.place.universeId) {
          const det = await request({
            url: "https://games.roblox.com/v1/games?universeIds=" + out.place.universeId,
            headers: { "User-Agent": BROWSER_UA, Accept: "application/json" },
          });
          let g = null;
          try { g = JSON.parse(det.body.toString("utf8")).data[0]; } catch (e) {}
          if (g) {
            out.place.name = g.name;
            out.place.creator = g.creator;
            out.place.maxPlayers = g.maxPlayers;
            out.place.playing = g.playing;
            out.place.isContentRestricted = g.isContentRestricted;
            out.place.ownedByYou = !!(g.creator && g.creator.id === v.user.id);
          }
        }

        const metaOpts = {
          url: "https://gamejoin.roblox.com/v1/join-game-metadata",
          method: "POST",
          headers: {
            Cookie: session.cookie,
            "Content-Type": "application/json",
            Accept: "application/json",
            "User-Agent": BROWSER_UA,
          },
          body: Buffer.from(JSON.stringify({ placeId: Number(placeId) })),
        };
        let meta = await request(metaOpts);
        if (meta.status === 403 && meta.headers["x-csrf-token"]) {
          // This lookup is diagnostic only, but it still requires the normal
          // Roblox CSRF challenge/retry to return playability for this user.
          metaOpts.headers.Cookie = session.cookie || metaOpts.headers.Cookie;
          metaOpts.headers["X-CSRF-Token"] = meta.headers["x-csrf-token"];
          meta = await request(metaOpts);
        }
        let m = null;
        try { m = JSON.parse(meta.body.toString("utf8")); } catch (e) {}
        out.join = {
          httpStatus: meta.status,
          status: m && typeof m.status === "number" ? m.status : null,
          playabilityStatus: (m && m.playabilityStatus) || null,
          message: (m && (m.message || (m.errors && m.errors[0] && m.errors[0].message))) || null,
        };

        const play = out.join.playabilityStatus;
        if (play && play !== "Ok") {
          out.verdict = play === "Unplayable" ? "UNPLAYABLE" : "RESTRICTED";
          out.remedy =
            play === "Unplayable"
              ? "Roblox marks this place as unplayable (usually shut down or under review)."
              : "Roblox restricts this experience for this account (age, region, privacy or paid access).";
        } else if (out.join.status === 12) {
          out.verdict = "NOT_AUTHORIZED";
          out.remedy = "gamejoin refused this account even though the session is valid. Check the experience's privacy setting.";
        }
      } catch (e) {
        out.verdict = "LOOKUP_FAILED";
        out.error = e.message;
      }

      return json(res, 200, out);
    })();
    return;
  }

  /* ---- client settings: user-channel with a query string ----
     The engine asks for /clientsettings/v2/user-channel?binaryType=WebClientApp.
     On disk the file is named user-channel-WebClientApp, so the plain path
     lookup misses and the engine logs a failed fetch. Answer it explicitly. */
  if (p === "/clientsettings/v2/user-channel") {
    const bin = parsed.searchParams.get("binaryType") || "WebClientApp";
    const f = path.join(ROOT, "clientsettings", "v2", "user-channel-" + bin);
    let body = '{"channelName":"LIVE"}';
    try { body = fs.readFileSync(f, "utf8").trim() || body; } catch (e) {}
    return json(res, 200, JSON.parse(body));
  }

  /* ---- dynamic authenticated user (the client's own auth probe) ----

     The WebClient (and the real roblox.com web app) probe
     `./user/v1/users/authenticated`. On roblox.com that path is answered by
     the site; here it must be answered by the *authoritative* endpoint,
     https://users.roblox.com/v1/users/authenticated, using the .ROBLOSECURITY
     session we detected from this browser. So instead of inventing a user we
     forward the probe to the real endpoint and pass its status and body back
     verbatim. That means the client sees exactly what roblox.com would tell
     it: 200 + {id,name,displayName} when signed in, 401 + the real
     {"errors":[{"code":9002,...}]} body when not.

     If no session is cached yet, try the same-browser CDP detection first so
     this works without the user pressing anything.
  -------------------------------------------------------------------------- */
  if (/(?:^|\/)users?\/v1\/users\/authenticated\/?$/.test(p)) {
    (async () => {
      if (!session.cookie) {
        const auto = await autoDetectCDP(requestOrigin(req));
        if (!auto.authenticated) {
          const body = JSON.stringify({
            errors: [{ code: 9002, subcode: 0, message: "Authentication token is missing" }],
          });
          res.writeHead(401, Object.assign({
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": Buffer.byteLength(body),
            "Cache-Control": "no-store",
          }, API_HEADERS));
          return res.end(body);
        }
      }
      try {
        const r = await request({
          url: "https://users.roblox.com/v1/users/authenticated",
          headers: {
            Cookie: session.cookie,
            Accept: "application/json",
            "User-Agent": BROWSER_UA,
            "Accept-Language": "en-US,en;q=0.9",
          },
        });
        // Keep the cached identity in sync with what Roblox just returned.
        if (r.status === 200) {
          try {
            const u = JSON.parse(r.body.toString("utf8"));
            if (u && u.id) {
              session.user = { id: u.id, name: u.name, displayName: u.displayName || u.name };
              saveSession();
            }
          } catch (e) {}
        }
        res.writeHead(r.status, Object.assign({
          "Content-Type": r.headers["content-type"] || "application/json; charset=utf-8",
          "Content-Length": r.body.length,
          "Cache-Control": "no-store",
        }, API_HEADERS));
        return res.end(r.body);
      } catch (e) {
        return json(res, 502, { errors: [{ code: 0, message: "upstream error: " + e.message }] });
      }
    })();
    return;
  }

  /* ---- static files ---- */
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.writeHead(405, { "Content-Type": "text/plain" });
    return res.end("method not allowed");
  }

  let rel = decodeURIComponent(p);
  if (rel === "/" || rel === "") rel = "/index.html";

  const filePath = path.resolve(ROOT, "." + rel);
  if (filePath !== ROOT && !filePath.startsWith(ROOT + path.sep)) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    return res.end("forbidden");
  }

  fs.stat(filePath, (err, st) => {
    if (err || !st.isFile()) {
      const wantsHtml = String(req.headers.accept || "").indexOf("text/html") !== -1;
      if (p.startsWith("/api/")) return json(res, 404, { error: "not found" });
      // Anything under the Next.js assetPrefix that is not on disk (CSS,
      // favicon, lazily-imported chunks, .wasm, ...) is fetched from
      // play.roblox.com and re-served same-origin. The webpack runtime's
      // publicPath is "./038e4bd.../_next/", i.e. relative to this host, so
      // every lazy chunk lands here; without this hop those requests 404.
      if (p.startsWith("/" + ASSET_PREFIX + "/")) {
        /* ---- engine worker bootstrap: install the API proxy in the worker --
           The wasm engine does all of its HTTP with XMLHttpRequest from inside
           a Web Worker (stub.js imports WebClient.js). A shim installed on the
           page window never reaches that worker, so the engine's requests went
           out cross-origin with this page's Origin header, Roblox rejected
           them, and the engine surfaced

               HttpError: Unknown url { "https://gamejoin.roblox.com/v1/join-game" }
               [LIFECYCLE] joinGameFailed state=0

           stub.js is same-origin and served by this server, so rewrite it to
           route every *.roblox.com / *.rbxcdn.com request through /api/p
           before the engine script is imported. */
        if (p === "/" + ASSET_PREFIX + "/assets/webclient/stub.js") {
          return request({
            url: "https://play.roblox.com" + p,
            method: "GET",
            headers: { Accept: "*/*", "User-Agent": BROWSER_UA, "Accept-Encoding": "identity" },
          })
            .then((r) => {
              const src = r.body.toString("utf8");
              const shim = ENGINE_WORKER_SHIM;
              const anchor = "importScripts(engineScriptUrl);";
              const out = Buffer.from(
                src.indexOf(anchor) !== -1 ? src.replace(anchor, shim + "\n  " + anchor) : shim + "\n" + src,
                "utf8"
              );
              res.writeHead(200, Object.assign({
                "Content-Type": "application/javascript; charset=utf-8",
                "Content-Length": String(out.length),
                "Cache-Control": "no-store",
              }, API_HEADERS));
              console.log("[patch] engine worker stub rewritten (proxy shim injected)");
              return res.end(req.method === "HEAD" ? undefined : out);
            })
            .catch(() => proxyRequest(req, res, "https://play.roblox.com" + p));
        }
        /* ---- engine bootstrap chunk: patch two hardcoded behaviours --------
           pages/games/start-*.js is baked into Roblox's build and does two
           things that break a self-hosted client:

             1. It seeds localStorage with a stale engine version
                ("version-f4a4dba57f874ad0"). The CDN answers 403 for that
                version, so the engine never boots.
             2. On a 401 from users.roblox.com/v1/users/authenticated it does a
                full-page navigation to https://www.roblox.com/login, throwing
                the user out of this app.

           Rewrite both fragments on the way through: use the live version and
           call the page's own sign-in prompt instead of leaving. */
        if (/^\/[^/]+\/_next\/static\/chunks\/pages\/games\/start-[^/]+\.js$/.test(p)) {
          return request({
            url: "https://play.roblox.com" + p,
            method: "GET",
            headers: { Accept: "*/*", "User-Agent": BROWSER_UA, "Accept-Encoding": "identity" },
          })
            .then((r) => {
              let src = r.body.toString("utf8");
              const before = src;
              // 1. live engine version instead of the baked-in stale one
              src = src.replace(
                /"version-f4a4dba57f874ad0"/g,
                '(window.__RBX_ENGINE_VERSION||"version-f4a4dba57f874ad0")'
              );
              // 2. stay in the app instead of navigating to roblox.com/login
              src = src.replace(
                /void window\.location\.replace\("https:\/\/www\."\.concat\(s,"\/login"\)\)/g,
                "void(window.__rbxNeedLogin&&window.__rbxNeedLogin())"
              );
              const out = Buffer.from(src, "utf8");
              res.writeHead(200, Object.assign({
                "Content-Type": "application/javascript; charset=utf-8",
                "Content-Length": String(out.length),
                "Cache-Control": "no-store",
              }, API_HEADERS));
              if (before !== src) {
                console.log("[patch] games/start chunk rewritten (" + p + ")");
              }
              return res.end(req.method === "HEAD" ? undefined : out);
            })
            .catch(() => proxyRequest(req, res, "https://play.roblox.com" + p));
        }
        return proxyRequest(req, res, "https://play.roblox.com" + p);
      }
      // A missing service worker is fatal and easy to misread as a network
      // problem, so say exactly what is wrong and where the file should be.
      if (path.basename(p) === "coi-serviceworker.js") {
        res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
        return res.end(
          "coi-serviceworker.js is missing from " + ROOT + "\n" +
          "The page asks for it at /coi-serviceworker.js (the ?v=4 is only a\n" +
          "cache-busting query string, not a separate file).\n" +
          "Restore it with:  unzip -o RobloxWeb-modded.zip RobloxWeb/coi-serviceworker.js\n"
        );
      }
      if (!wantsHtml) {
        res.writeHead(404, { "Content-Type": "text/plain" });
        return res.end("not found");
      }
      const idx = path.join(ROOT, "index.html");
      return fs.readFile(idx, (e2, buf) => {
        if (e2) {
          res.writeHead(404, { "Content-Type": "text/plain" });
          return res.end("not found");
        }
        const html = injectSession(buf.toString("utf8"));
        res.writeHead(200, Object.assign({ "Content-Type": MIME[".html"], "Cache-Control": "no-store" }, ISOLATION_HEADERS));
        res.end(req.method === "HEAD" ? undefined : html);
      });
    }

    const ext = path.extname(filePath).toLowerCase();
    const isHtml = ext === ".html";
    // A service worker script must never be cached as immutable: the browser
    // would keep running an old worker (and an old proxy/override table) even
    // after the file on disk changed.
    const isWorker = path.basename(filePath) === "coi-serviceworker.js";
    const headers = Object.assign(
      {
        "Content-Type": MIME[ext] || "application/octet-stream",
        "Cache-Control": isHtml
          ? "no-store"
          : isWorker
          ? "no-cache, no-store, must-revalidate"
          : "public, max-age=31536000, immutable",
      },
      ISOLATION_HEADERS
    );
    if (isWorker) {
      headers["Service-Worker-Allowed"] = "/";
      headers["Pragma"] = "no-cache";
      headers["Expires"] = "0";
    }

    if (!isHtml) {
      headers["Content-Length"] = st.size;
      res.writeHead(200, headers);
      if (req.method === "HEAD") return res.end();
      return fs.createReadStream(filePath).pipe(res);
    }

    fs.readFile(filePath, (e2, buf) => {
      if (e2) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        return res.end("read error");
      }
      let html = buf.toString("utf8");
      if (path.basename(filePath) === "client.html") html = injectSession(html);
      headers["Content-Length"] = Buffer.byteLength(html);
      res.writeHead(200, headers);
      res.end(req.method === "HEAD" ? undefined : html);
    });
  });
});

server.on("clientError", (err, socket) => {
  try { socket.end("HTTP/1.1 400 Bad Request\r\n\r\n"); } catch (e) {}
});

loadSession();

// The app handles live Roblox session cookies. Keep it reachable only from
// this computer unless the operator explicitly opts into network exposure.
const HOST = process.env.HOST || "127.0.0.1";

server.listen(PORT, HOST, () => {
  console.log(`[server] http://localhost:${PORT}/`);
  console.log(`[server] build: ${BUILD_ID}`);
  console.log(`[server] isolation headers: COOP same-origin / COEP credentialless`);
  console.log(`[server] same-origin API proxy: /api/p?url=<encoded url>`);
  console.log(`[server] session: ${session.cookie ? "loaded (" + (session.user ? "@" + session.user.name : "unverified") + ")" : "none yet — use the login screen"}`);
  if (session.cookie && !session.user) {
    validateCookie(session.cookie).then((v) => {
      if (v.ok) {
        session.user = v.user;
        saveSession();
        console.log(`[auth] signed in as @${v.user.name} (${v.user.displayName})`);
      } else {
        console.log(`[auth] stored session is no longer valid: ${v.error}`);
        clearSession();
      }
    });
  }
  // If nothing is cached, quietly look for an already signed-in Roblox session
  // in the browser this server is being viewed in. This is the "same browser"
  // case: open the app while logged in at roblox.com and it is already you.
  if (!session.cookie) {
    autoDetectCDP().then((a) => {
      if (a.authenticated) {
        console.log(`[auth] same-browser session detected: @${a.user.name} (${a.source})`);
      } else {
        console.log("[auth] no same-browser session yet — sign in at roblox.com, then reload");
      }
    }).catch(() => {});
  }
});
