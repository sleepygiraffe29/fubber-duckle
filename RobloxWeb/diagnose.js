#!/usr/bin/env node
/*
  diagnose.js — print exactly what the browser-cookie detector can see.
  Run this on the machine where your browser is signed in to roblox.com:

      node diagnose.js
      node diagnose.js --json

  It never prints the cookie value itself, only whether one was found and
  decrypted.
*/

"use strict";

const cd = require("./lib/cookie-detect");
const fs = require("fs");
const os = require("os");

const asJson = process.argv.includes("--json");

const scan = cd.scan();
const profiles = cd.chromiumProfiles();

const report = {
  platform: cd.platform,
  node: process.version,
  home: os.homedir(),
  profiles: profiles.map((p) => ({
    browser: p.browser,
    dir: p.dir,
    explicit: p.explicit,
    exists: fs.existsSync(p.dir),
    key: cd.cookieKeyFor(p.dir, p.browser).note,
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
  keychainAllowed: cd.keychainAllowed(),
  hint: cd.explain(scan.reports),
};

if (asJson) {
  console.log(JSON.stringify(report, null, 2));
  process.exit(0);
}

const line = (s) => console.log(s);

line("");
line("  Roblox cookie detection - diagnostic");
line("  " + "=".repeat(46));
line("  platform : " + report.platform);
line("  node     : " + report.node);
line("  home     : " + report.home);
line("");

line("  Browser profiles considered (" + report.profiles.length + "):");
for (const p of report.profiles) {
  if (!p.exists) continue;
  line("    [found] " + p.browser);
  line("            " + p.dir);
  line("            key: " + p.key);
}
if (!report.profiles.some((p) => p.exists)) line("    none");

line("");
line("  Cookie databases read (" + report.databases.length + "):");
if (!report.databases.length) line("    none");
for (const d of report.databases) {
  line("    " + d.path);
  line(
    "      " +
      (d.size == null ? "no file" : Math.round(d.size / 1024) + " KB") +
      " | roblox rows: " +
      d.robloxRows +
      " | decrypted: " +
      d.decrypted +
      " | key: " +
      d.key
  );
  if (d.appBound) line("      !! App-Bound Encryption (v20) - not decryptable by third-party software");
  for (const e of d.errors) line("      !! " + e);
}

line("");
line("  Keychain access allowed: " + (report.keychainAllowed ? "yes" : "no (no macOS prompt will appear)"));
line("  Usable .ROBLOSECURITY candidates: " + report.candidates);
line("");
line("  Verdict: " + report.hint);
line("");

if (report.candidates === 0) {
  line("  Next steps");
  line("  ----------");
  if (report.platform === "win32") {
    line("  1. Make sure Chrome is fully closed (check Task Manager for chrome.exe).");
    line("  2. Chrome 127+ on Windows uses App-Bound Encryption (v20). If the report");
    line("     above says v20, no external tool can decrypt it. Use the manual option:");
    line("     DevTools -> Application -> Cookies -> https://www.roblox.com.");
  } else if (report.platform === "darwin") {
    line("  1. Keychain access is OFF by default so macOS never prompts you.");
    line("     To grant it once:  RBX_KEYCHAIN=1 node diagnose.js");
    line("     (macOS will ask; click Always Allow and it will not ask again.)");
    line("  2. The password is then cached in ~/.rbx-safe-storage.json (mode 0600),");
    line("     so no further prompts appear, ever.");
  } else {
    line("  1. Make sure Chrome/Chromium is signed in at roblox.com.");
    line("  2. If you use a keyring (GNOME/KDE), the cookie may use a different key;");
    line("     the manual cookie option always works.");
  }
  line("  3. Or point the detector at a specific profile:");
  line("     CHROME_PROFILE_DIR=\"/path/to/Profile\" node diagnose.js");
  line("");
}
