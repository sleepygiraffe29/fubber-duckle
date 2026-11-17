/*
  cookie-detect.js — read the .ROBLOSECURITY cookie that a real browser has
  already stored on this machine, and explain exactly what happened.

  Chromium-family cookie encryption differs per platform:

    Linux    AES-128-CBC, key = PBKDF2("peanuts", "saltysalt", 1, 16, sha1)
             (v10 / v11)
    macOS    AES-128-CBC, key = PBKDF2(<Keychain "X Safe Storage">, "saltysalt",
             1003, 16, sha1)  (v10 / v11)
    Windows  AES-256-GCM, key = DPAPI(Local State -> os_crypt.encrypted_key)
             (v10, Chrome 80+)
    Windows  "v20" = App-Bound Encryption (Chrome 127+). The key is sealed to
             the Chrome executable by a system service and cannot be unwrapped
             offline by a third-party process. We detect it and say so instead
             of silently returning nothing.

  Every candidate is reported with a reason, so the UI can tell the user what
  to do next instead of just "not found".
*/

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { execFileSync } = require("child_process");

const COOKIE_NAME = ".ROBLOSECURITY";

/* ------------------------------------------------------------------ helpers */

function normalizeCookie(raw) {
  let c = String(raw || "").trim().replace(/^cookie:\s*/i, "");
  if (!c) return "";
  const m = c.match(/\.ROBLOSECURITY=([^;]+)/i);
  if (m) return ".ROBLOSECURITY=" + m[1].trim();
  if (c.indexOf("=") === -1) return ".ROBLOSECURITY=" + c;
  return c;
}

function exists(p) {
  try {
    return fs.existsSync(p);
  } catch (e) {
    return false;
  }
}

function statOf(p) {
  try {
    const s = fs.statSync(p);
    return { size: s.size, mtime: s.mtime.toISOString() };
  } catch (e) {
    return null;
  }
}

function isProfileDirName(name) {
  return name === "Default" || /^Profile \d+$/.test(name) || name === "Guest Profile";
}

/* --------------------------------------------------- chromium profile paths */

function chromiumRoots() {
  const home = os.homedir();
  const roots = [];
  const push = (label, p) => roots.push({ label, root: p });

  if (process.platform === "linux") {
    const cfg = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
    push("Google Chrome", path.join(cfg, "google-chrome"));
    push("Google Chrome (beta)", path.join(cfg, "google-chrome-beta"));
    push("Google Chrome (unstable)", path.join(cfg, "google-chrome-unstable"));
    push("Chromium", path.join(cfg, "chromium"));
    push("Brave", path.join(cfg, "BraveSoftware/Brave-Browser"));
    push("Microsoft Edge", path.join(cfg, "microsoft-edge"));
    push("Vivaldi", path.join(cfg, "vivaldi"));
    push("Opera", path.join(cfg, "opera"));
    push("Chrome (snap)", path.join(home, "snap/chromium/common/chromium"));
  } else if (process.platform === "darwin") {
    const app = path.join(home, "Library/Application Support");
    push("Google Chrome", path.join(app, "Google/Chrome"));
    push("Google Chrome (beta)", path.join(app, "Google/Chrome Beta"));
    push("Google Chrome (canary)", path.join(app, "Google/Chrome Canary"));
    push("Chromium", path.join(app, "Chromium"));
    push("Brave", path.join(app, "BraveSoftware/Brave-Browser"));
    push("Microsoft Edge", path.join(app, "Microsoft Edge"));
    push("Vivaldi", path.join(app, "Vivaldi"));
    push("Opera", path.join(app, "com.operasoftware.Opera"));
  } else if (process.platform === "win32") {
    const local = process.env.LOCALAPPDATA || path.join(home, "AppData/Local");
    push("Google Chrome", path.join(local, "Google/Chrome/User Data"));
    push("Google Chrome (beta)", path.join(local, "Google/Chrome Beta/User Data"));
    push("Google Chrome (canary)", path.join(local, "Google/Chrome SxS/User Data"));
    push("Chromium", path.join(local, "Chromium/User Data"));
    push("Brave", path.join(local, "BraveSoftware/Brave-Browser/User Data"));
    push("Microsoft Edge", path.join(local, "Microsoft/Edge/User Data"));
    push("Vivaldi", path.join(local, "Vivaldi/User Data"));
    push(
      "Opera",
      path.join(process.env.APPDATA || path.join(home, "AppData/Roaming"), "Opera Software/Opera Stable")
    );
  }
  return roots;
}

/**
 * Every place a Chromium-family cookie DB might live, most likely first.
 * Explicit overrides (CHROME_PROFILE_DIR / BROWSER_DATA_DIR) are honoured and
 * may point at either a "User Data" root or a single profile directory.
 */
function browserFamilyForLabel(label) {
  const name = String(label || "").toLowerCase();
  if (name.includes("firefox")) return "firefox";
  if (name.includes("brave")) return "brave";
  if (name.includes("edge")) return "edge";
  if (name.includes("opera")) return "opera";
  if (name.includes("vivaldi")) return "vivaldi";
  return "chrome";
}

function chromiumProfiles(options) {
  options = options || {};
  const out = [];
  const seen = new Set();
  const add = (dir, browser, explicit) => {
    if (!dir) return;
    const key = path.resolve(dir);
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ dir: key, browser: browser || "Chromium", explicit: !!explicit });
  };

  // 1. Explicit overrides.
  for (const envName of ["CHROME_PROFILE_DIR", "BROWSER_DATA_DIR"]) {
    const v = process.env[envName];
    if (!v) continue;
    if (isProfileDirName(path.basename(v))) add(v, "Chromium (from " + envName + ")", true);
    else {
      add(v, "Chromium (from " + envName + ")", true);
      add(path.join(v, "Default"), "Chromium (from " + envName + ")", true);
    }
  }

  // 2. Sandbox / bundled browser data (this build ships one).
  const sandboxDirs = [path.join(__dirname, "..", ".browser_data")];
  let probe = path.join(__dirname, "..");
  for (let i = 0; i < 4; i++) {
    probe = path.dirname(probe);
    sandboxDirs.push(path.join(probe, ".browser_data"));
    if (probe === path.dirname(probe)) break;
  }
  sandboxDirs.push("/workspace/.browser_data");
  for (const d of sandboxDirs) {
    add(d, "Bundled browser");
    add(path.join(d, "Default"), "Bundled browser");
  }

  // 3. Real browser installs.
  for (const { label, root } of chromiumRoots()) {
    if (!exists(root)) continue;
    add(root, label);
    add(path.join(root, "Default"), label);
    let entries = [];
    try {
      entries = fs.readdirSync(root, { withFileTypes: true });
    } catch (e) {
      entries = [];
    }
    for (const e of entries) {
      if (e.isDirectory() && isProfileDirName(e.name)) add(path.join(root, e.name), label);
    }
  }

  return options.browserFamily
    ? out.filter((profile) => browserFamilyForLabel(profile.browser) === options.browserFamily)
    : out;
}

function cookieDbCandidates(profileDir) {
  // Newer Chrome keeps cookies under Network/; older builds keep them at the root.
  return [path.join(profileDir, "Network", "Cookies"), path.join(profileDir, "Cookies")];
}

/* ------------------------------------------------------------ key derivation */

const keyCache = new Map();

function pbkdf2(password, iterations) {
  return crypto.pbkdf2Sync(password, "saltysalt", iterations, 16, "sha1");
}

/* ------------------------------------------------------- macOS Safe Storage

   Reading the Safe Storage password from the Keychain makes macOS show a
   "security wants to use your confidential information" dialog. That dialog
   appears once per calling binary, so a naive implementation can prompt on
   every profile and every request — which is miserable.

   Rules here:
     1. Resolve the password AT MOST ONCE per process (global memo).
     2. Persist it to ~/.rbx-safe-storage.json (mode 0600) so later runs never
        prompt again.
     3. Honour RBX_SAFE_STORAGE_PASSWORD to skip the Keychain entirely.
     4. Honour RBX_NO_KEYCHAIN=1 to skip it and fall back to the manual cookie.
     5. Try one service name at a time, most likely first, and stop on success.
*/

const SAFE_STORAGE_FILE = path.join(os.homedir(), ".rbx-safe-storage.json");

let safeStorageMemo; // undefined = not resolved yet, null = unavailable

// On macOS the Keychain shows a system dialog. We never trigger it unless the
// user explicitly asks (RBX_KEYCHAIN=1, or the "Allow Keychain access once"
// button on the login screen).
let keychainAllowed = process.env.RBX_KEYCHAIN === "1" || process.env.RBX_KEYCHAIN === "true";

function allowKeychain() {
  keychainAllowed = true;
  safeStorageMemo = undefined;
  keyCache.clear();
}

function readSafeStorageCache() {
  try {
    const j = JSON.parse(fs.readFileSync(SAFE_STORAGE_FILE, "utf8"));
    if (j && typeof j.password === "string" && j.password) {
      return { password: j.password, service: j.service || "cached", cached: true };
    }
  } catch (e) {
    /* no cache */
  }
  return null;
}

function writeSafeStorageCache(entry) {
  try {
    fs.writeFileSync(
      SAFE_STORAGE_FILE,
      JSON.stringify({ password: entry.password, service: entry.service, savedAt: new Date().toISOString() }, null, 2),
      { mode: 0o600 }
    );
    try {
      fs.chmodSync(SAFE_STORAGE_FILE, 0o600);
    } catch (e) {}
  } catch (e) {
    /* best effort */
  }
}

function macSafeStoragePassword(browserLabel) {
  if (safeStorageMemo !== undefined) return safeStorageMemo;

  // 1. Explicit password from the environment: no Keychain, no prompt.
  const fromEnv = process.env.RBX_SAFE_STORAGE_PASSWORD;
  if (fromEnv) {
    safeStorageMemo = { password: fromEnv, service: "RBX_SAFE_STORAGE_PASSWORD", cached: true };
    return safeStorageMemo;
  }

  // 2. Opt out entirely — and on macOS that is the default, so no dialog
  //    ever appears unless the user asked for it.
  if (process.env.RBX_NO_KEYCHAIN === "1" || process.env.RBX_NO_KEYCHAIN === "true" || !keychainAllowed) {
    safeStorageMemo = null;
    return safeStorageMemo;
  }

  // 3. Previously saved password: no prompt.
  const cached = readSafeStorageCache();
  if (cached) {
    safeStorageMemo = cached;
    return safeStorageMemo;
  }

  // 4. One Keychain lookup. Only the single most likely service name is tried
  //    first; the rest are fallbacks that only run if the first one is absent.
  const base = String(browserLabel || "").replace(/\s*\(.*\)\s*$/, "").trim();
  const services = [];
  if (base && base !== "Bundled browser") services.push(base + " Safe Storage");
  for (const s of [
    "Chrome Safe Storage",
    "Chromium Safe Storage",
    "Brave Safe Storage",
    "Microsoft Edge Safe Storage",
    "Vivaldi Safe Storage",
    "Opera Safe Storage",
  ]) {
    if (!services.includes(s)) services.push(s);
  }

  for (const svc of services) {
    try {
      const pw = execFileSync("security", ["find-generic-password", "-w", "-s", svc], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
        timeout: 8000,
      }).trim();
      if (pw) {
        const entry = { password: pw, service: svc };
        writeSafeStorageCache(entry);
        safeStorageMemo = entry;
        return safeStorageMemo;
      }
    } catch (e) {
      // errSecItemNotFound (44) means this browser isn't installed — keep going.
      // Anything else (user denied, timeout) means stop asking.
      const msg = String((e && (e.stderr || e.message)) || "");
      if (/The user name or passphrase you entered is not correct|User interaction is not allowed|canceled/i.test(msg)) {
        break;
      }
    }
  }

  safeStorageMemo = null;
  return safeStorageMemo;
}

function windowsDpapiUnprotect(blobB64) {
  const script = [
    "$ErrorActionPreference='Stop'",
    "Add-Type -AssemblyName System.Security",
    "$b=[Convert]::FromBase64String($env:RBX_DPAPI_BLOB)",
    "$u=[System.Security.Cryptography.ProtectedData]::Unprotect($b,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser)",
    "[Convert]::ToBase64String($u)",
  ].join("; ");
  try {
    const out = execFileSync("powershell", ["-NoProfile", "-NonInteractive", "-Command", script], {
      encoding: "utf8",
      timeout: 15000,
      stdio: ["ignore", "pipe", "ignore"],
      env: Object.assign({}, process.env, { RBX_DPAPI_BLOB: blobB64 }),
    }).trim();
    if (!out) return null;
    return Buffer.from(out, "base64");
  } catch (e) {
    return null;
  }
}

/**
 * Returns { kind, key, note } describing how cookies in this profile are
 * encrypted, or { kind: "unknown", note } when we cannot get the key.
 *   kind: "cbc"  -> AES-128-CBC, 16-byte key
 *         "gcm"  -> AES-256-GCM, 32-byte key
 */
function cookieKeyFor(profileDir, browserLabel) {
  const cacheKey = profileDir + "|" + (browserLabel || "");
  if (keyCache.has(cacheKey)) return keyCache.get(cacheKey);

  let result;

  if (process.platform === "darwin") {
    const found = macSafeStoragePassword(browserLabel);
    if (found) {
      result = {
        kind: "cbc",
        key: pbkdf2(found.password, 1003),
        note: 'Keychain "' + found.service + '" (1003 PBKDF2 rounds)',
      };
    } else {
      result = {
        kind: "unknown",
        note:
          "Keychain access was not requested (macOS would show a system dialog). " +
          "Press \"Allow Keychain access once\" if you want to grant it, or use the manual cookie.",
      };
    }
  } else if (process.platform === "win32") {
    // Walk up from the profile dir to find "Local State".
    let dir = profileDir;
    let localState = null;
    for (let i = 0; i < 3; i++) {
      const candidate = path.join(dir, "Local State");
      if (exists(candidate)) {
        localState = candidate;
        break;
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    if (!localState) {
      result = { kind: "unknown", note: "Could not find Chrome's Local State file next to this profile." };
    } else {
      try {
        const j = JSON.parse(fs.readFileSync(localState, "utf8"));
        const encKeyB64 = j && j.os_crypt && j.os_crypt.encrypted_key;
        if (!encKeyB64) {
          result = { kind: "unknown", note: "Local State has no os_crypt.encrypted_key." };
        } else {
          const raw = Buffer.from(encKeyB64, "base64");
          const stripped = raw.slice(0, 5).toString("latin1") === "DPAPI" ? raw.slice(5) : raw;
          const key = windowsDpapiUnprotect(stripped.toString("base64"));
          result =
            key && key.length === 32
              ? { kind: "gcm", key, note: "DPAPI-protected AES-256-GCM key from Local State" }
              : { kind: "unknown", note: "DPAPI could not unwrap the Local State key." };
        }
      } catch (e) {
        result = { kind: "unknown", note: "Local State is unreadable: " + e.message };
      }
    }
  } else {
    // Linux and everything else: the classic "peanuts" key.
    result = { kind: "cbc", key: pbkdf2("peanuts", 1), note: 'PBKDF2("peanuts", 1 round)' };
  }

  keyCache.set(cacheKey, result);
  return result;
}

/* --------------------------------------------------------------- decryption */

function stripHostHash(plain, hostKey) {
  // Chrome 130+ prefixes the plaintext with SHA256(host_key).
  if (!plain || plain.length <= 32) return plain;
  const expected = crypto.createHash("sha256").update(hostKey || "").digest();
  if (plain.slice(0, 32).equals(expected)) return plain.slice(32);
  // Fallback heuristic: a 32-byte binary prefix followed by printable text.
  const tail = plain.slice(32);
  if (/^[\x20-\x7e]+$/.test(tail.toString("latin1"))) return tail;
  return plain;
}

/**
 * Decrypt one `encrypted_value` blob.
 * Returns { value } on success or { error, prefix } on failure.
 */
function decryptValue(enc, hostKey, keyInfo) {
  if (!enc || !enc.length) return { error: "empty value" };
  const buf = Buffer.isBuffer(enc) ? enc : Buffer.from(enc);

  // Plaintext cookie (Firefox-style, or Chrome with --disable-cookie-encryption).
  const prefix = buf.slice(0, 3).toString("latin1");
  if (prefix !== "v10" && prefix !== "v11" && prefix !== "v20") {
    const s = buf.toString("utf8");
    return s ? { value: s, plain: true } : { error: "unrecognised blob" };
  }
  if (prefix === "v20") {
    return {
      error:
        "v20 = Chrome App-Bound Encryption (Chrome 127+ on Windows). The key is sealed to chrome.exe by a system service and cannot be unwrapped by another program.",
      prefix,
      appBound: true,
    };
  }
  if (!keyInfo || keyInfo.kind === "unknown") {
    return { error: keyInfo ? keyInfo.note : "no decryption key available", prefix };
  }

  const payload = buf.slice(3);

  try {
    if (keyInfo.kind === "gcm") {
      if (payload.length < 28) return { error: "GCM payload too short", prefix };
      const nonce = payload.slice(0, 12);
      const tag = payload.slice(payload.length - 16);
      const ct = payload.slice(12, payload.length - 16);
      const d = crypto.createDecipheriv("aes-256-gcm", keyInfo.key, nonce);
      d.setAuthTag(tag);
      let out = Buffer.concat([d.update(ct), d.final()]);
      out = stripHostHash(out, hostKey);
      return { value: out.toString("utf8") };
    }

    const iv = Buffer.alloc(16, 0x20);
    const d = crypto.createDecipheriv("aes-128-cbc", keyInfo.key, iv);
    d.setAutoPadding(true);
    let out = Buffer.concat([d.update(payload), d.final()]);
    out = stripHostHash(out, hostKey);
    return { value: out.toString("utf8") };
  } catch (e) {
    return { error: "decrypt failed (" + e.message + ") — wrong key for this profile", prefix };
  }
}

/* ------------------------------------------------------------- database read */

function copyDb(dbPath) {
  // Chrome locks the DB on Windows and keeps a WAL on all platforms. Copy the
  // file (plus -wal / -shm) to a temp dir and read the copy, retrying briefly
  // in case the browser is mid-write.
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rbx-ck-"));
  const target = path.join(tmpDir, "Cookies");
  let lastErr = null;
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      fs.copyFileSync(dbPath, target);
      for (const suffix of ["-wal", "-shm"]) {
        try {
          if (exists(dbPath + suffix)) fs.copyFileSync(dbPath + suffix, target + suffix);
        } catch (e) {
          /* optional */
        }
      }
      return { dir: tmpDir, file: target };
    } catch (e) {
      lastErr = e;
      const end = Date.now() + 120;
      while (Date.now() < end) {
        /* tiny synchronous backoff */
      }
    }
  }
  try {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch (e) {}
  throw lastErr || new Error("copy failed");
}

function openDb(file) {
  const { DatabaseSync } = require("node:sqlite");
  return new DatabaseSync(file, { readOnly: true });
}

/**
 * Inspect one cookie DB: how many roblox rows, and what we could decrypt.
 * Always returns a structured report — never throws.
 */
function inspectChromiumDb(dbPath, profile, keyInfo) {
  const report = {
    browser: profile.browser,
    profile: profile.dir,
    path: dbPath,
    exists: exists(dbPath),
    stat: statOf(dbPath),
    key: keyInfo ? keyInfo.note : "",
    robloxRows: 0,
    cookies: [],
    errors: [],
  };
  if (!report.exists) {
    report.errors.push("file does not exist");
    return report;
  }

  let copied = null;
  try {
    copied = copyDb(dbPath);
  } catch (e) {
    report.errors.push(
      "could not copy the cookie database (" +
        (e.code || e.message) +
        "). Close the browser completely and try again."
    );
    return report;
  }

  let db = null;
  try {
    db = openDb(copied.file);
    const rows = db
      .prepare(
        "SELECT host_key, name, value, encrypted_value FROM cookies WHERE host_key LIKE '%roblox%' OR name = ?"
      )
      .all(COOKIE_NAME);

    report.robloxRows = rows.length;

    for (const row of rows) {
      if (row.name !== COOKIE_NAME) continue;
      const enc = row.encrypted_value;
      const prefix = enc && enc.length ? Buffer.from(enc).slice(0, 3).toString("latin1") : "plain";
      let value = row.value || "";

      if (!value && enc && enc.length) {
        const dec = decryptValue(enc, row.host_key, keyInfo);
        if (dec.error) {
          report.errors.push(row.host_key + ": " + dec.error);
          report.appBound = report.appBound || !!dec.appBound;
          continue;
        }
        value = dec.value;
      }
      if (!value) continue;

      const m = String(value).match(/\.ROBLOSECURITY=([^;]+)/);
      if (m) value = m[1];
      value = value.trim();
      if (!value) continue;

      report.cookies.push({ host: row.host_key, value, prefix });
    }
  } catch (e) {
    report.errors.push("sqlite read failed: " + e.message);
  } finally {
    if (db) {
      try {
        db.close();
      } catch (e) {}
    }
    if (copied) {
      try {
        fs.rmSync(copied.dir, { recursive: true, force: true });
      } catch (e) {}
    }
  }
  return report;
}

/* ---------------------------------------------------------------- firefox */

function firefoxProfiles() {
  const home = os.homedir();
  const bases = [];
  if (process.platform === "darwin") {
    bases.push(path.join(home, "Library/Application Support/Firefox/Profiles"));
  } else if (process.platform === "win32") {
    bases.push(
      path.join(process.env.APPDATA || path.join(home, "AppData/Roaming"), "Mozilla/Firefox/Profiles")
    );
  } else {
    bases.push(
      path.join(home, ".mozilla/firefox"),
      path.join(home, "snap/firefox/common/.mozilla/firefox")
    );
  }
  const out = [];
  for (const base of bases) {
    let entries = [];
    try {
      entries = fs.readdirSync(base, { withFileTypes: true });
    } catch (e) {
      continue;
    }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      const p = path.join(base, e.name, "cookies.sqlite");
      if (exists(p)) out.push(p);
    }
  }
  return out;
}

function inspectFirefoxDb(dbPath) {
  const report = {
    browser: "Firefox",
    profile: path.dirname(dbPath),
    path: dbPath,
    exists: exists(dbPath),
    stat: statOf(dbPath),
    key: "plaintext (no encryption)",
    robloxRows: 0,
    cookies: [],
    errors: [],
  };
  let copied = null;
  let db = null;
  try {
    copied = copyDb(dbPath);
    db = openDb(copied.file);
    const rows = db
      .prepare("SELECT host, name, value FROM moz_cookies WHERE host LIKE '%roblox%' OR name = ?")
      .all(COOKIE_NAME);
    report.robloxRows = rows.length;
    for (const r of rows) {
      if (r.name !== COOKIE_NAME || !r.value) continue;
      let v = String(r.value).trim();
      const m = v.match(/\.ROBLOSECURITY=([^;]+)/);
      if (m) v = m[1];
      if (v) report.cookies.push({ host: r.host, value: v, prefix: "plain" });
    }
  } catch (e) {
    report.errors.push("sqlite read failed: " + e.message);
  } finally {
    if (db) {
      try {
        db.close();
      } catch (e) {}
    }
    if (copied) {
      try {
        fs.rmSync(copied.dir, { recursive: true, force: true });
      } catch (e) {}
    }
  }
  return report;
}

/* ------------------------------------------------------------------ public */

/**
 * Scan every known browser profile. Returns:
 *   { reports: [...], candidates: [{cookie, source, path, browser}] }
 * `reports` is safe to show to the user; `candidates` still needs validating
 * against Roblox before it is trusted.
 */
function scan(options) {
  options = options || {};
  const reports = [];
  const candidates = [];

  for (const profile of chromiumProfiles(options)) {
    const keyInfo = cookieKeyFor(profile.dir, profile.browser);
    for (const db of cookieDbCandidates(profile.dir)) {
      if (!exists(db)) continue;
      const r = inspectChromiumDb(db, profile, keyInfo);
      reports.push(r);
      for (const c of r.cookies) {
        candidates.push({
          cookie: normalizeCookie(c.value),
          source: "browser cookie store (" + profile.browser + ")",
          path: db,
          browser: profile.browser,
        });
      }
    }
  }

  for (const db of options.browserFamily && options.browserFamily !== "firefox" ? [] : firefoxProfiles()) {
    const r = inspectFirefoxDb(db);
    reports.push(r);
    for (const c of r.cookies) {
      candidates.push({
        cookie: normalizeCookie(c.value),
        source: "Firefox cookie store",
        path: db,
        browser: "Firefox",
      });
    }
  }

  // De-duplicate identical cookie values (same profile seen twice).
  const seen = new Set();
  const unique = [];
  for (const c of candidates) {
    if (!c.cookie || seen.has(c.cookie)) continue;
    seen.add(c.cookie);
    unique.push(c);
  }

  return { reports, candidates: unique };
}

/** A short, human-readable summary of why nothing was found. */
function explain(reports) {
  if (!reports.length) {
    return "No browser cookie database was found on this machine. If your browser lives somewhere unusual, start the server with CHROME_PROFILE_DIR=/path/to/profile.";
  }
  const withRows = reports.filter((r) => r.robloxRows > 0);
  if (withRows.length) {
    const appBound = reports.some((r) => r.appBound);
    if (appBound) {
      return "Chrome is using App-Bound Encryption (v20, Chrome 127+ on Windows), which third-party programs cannot decrypt. Use the manual cookie option below, or launch Chrome with --disable-features=AppBoundEncryption and sign in again.";
    }
    return "A Roblox cookie row exists but could not be decrypted. See the details below.";
  }
  const readable = reports.filter((r) => r.stat);
  if (readable.length) {
    return (
      "Found " +
      readable.length +
      " cookie database(s), but none contained a .ROBLOSECURITY row. Sign in at roblox.com in that browser first, then retry."
    );
  }
  return "Cookie databases were located but none could be read. Close the browser completely and retry.";
}

module.exports = {
  COOKIE_NAME,
  normalizeCookie,
  chromiumProfiles,
  browserFamilyForLabel,
  firefoxProfiles,
  decryptValue,
  cookieKeyFor,
  scan,
  explain,
  allowKeychain,
  keychainAllowed: () => keychainAllowed,
  platform: process.platform,
};
