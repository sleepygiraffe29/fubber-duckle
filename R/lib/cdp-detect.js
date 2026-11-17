"use strict";
/*
 * Read the .ROBLOSECURITY cookie out of a running Chrome/Edge/Brave through the
 * DevTools Protocol.
 *
 * Why this exists
 * ---------------
 * On macOS, Chrome encrypts its cookie database with a key that lives in the
 * login Keychain. Decrypting it means a Keychain prompt (and this build refuses
 * to prompt by default). But Chrome will happily hand the *decrypted* cookie to
 * anything that speaks the DevTools Protocol on a local port -- no Keychain, no
 * prompt, no password. On Windows it also sidesteps App-Bound Encryption
 * ("v20") entirely, which no third-party decryptor can handle.
 *
 * The catch: Chrome only opens the debugging port if it was started with
 * --remote-debugging-port. So this module is a fast probe that fails cleanly
 * when the port is not there.
 *
 * No dependencies. Node's `net` + `crypto` are enough for a WebSocket client.
 */

const net = require("net");
const crypto = require("crypto");

const COOKIE_NAME = ".ROBLOSECURITY";

/* Ports people actually end up with. 9222 is the documented default. */
const DEFAULT_PORTS = [9222, 9223, 9224, 9229, 9333];

function ports() {
  const fromEnv = (process.env.RBX_CDP_PORT || "").trim();
  if (fromEnv) return fromEnv.split(",").map((s) => parseInt(s.trim(), 10)).filter(Boolean);
  return DEFAULT_PORTS;
}

/* ------------------------------------------------------------------ *
 * Minimal WebSocket client (RFC 6455, text frames, client-masked)
 * ------------------------------------------------------------------ */

function wsConnect(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    let u;
    try {
      u = new URL(url);
    } catch (e) {
      return reject(new Error("bad websocket url"));
    }
    const key = crypto.randomBytes(16).toString("base64");
    const host = u.hostname;
    const port = parseInt(u.port || "80", 10);
    const pathWithQuery = (u.pathname || "/") + (u.search || "");

    const sock = net.connect({ host, port });
    let settled = false;
    let buffer = Buffer.alloc(0);
    let handshakeDone = false;
    const listeners = [];

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        try { sock.destroy(); } catch (e) {}
        reject(new Error("websocket timeout"));
      }
    }, timeoutMs || 4000);

    function fail(err) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { sock.destroy(); } catch (e) {}
      reject(err);
    }

    sock.on("error", fail);
    sock.on("close", () => {
      if (!settled && !handshakeDone) fail(new Error("socket closed during handshake"));
    });

    sock.on("connect", () => {
      sock.write(
        "GET " + pathWithQuery + " HTTP/1.1\r\n" +
        "Host: " + host + ":" + port + "\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        "Sec-WebSocket-Key: " + key + "\r\n" +
        "Sec-WebSocket-Version: 13\r\n" +
        "\r\n"
      );
    });

    function parseFrames() {
      while (buffer.length >= 2) {
        const b0 = buffer[0];
        const b1 = buffer[1];
        const opcode = b0 & 0x0f;
        const masked = (b1 & 0x80) !== 0;
        let len = b1 & 0x7f;
        let offset = 2;

        if (len === 126) {
          if (buffer.length < offset + 2) return;
          len = buffer.readUInt16BE(offset);
          offset += 2;
        } else if (len === 127) {
          if (buffer.length < offset + 8) return;
          const hi = buffer.readUInt32BE(offset);
          const lo = buffer.readUInt32BE(offset + 4);
          len = hi * 4294967296 + lo;
          offset += 8;
        }

        let mask = null;
        if (masked) {
          if (buffer.length < offset + 4) return;
          mask = buffer.slice(offset, offset + 4);
          offset += 4;
        }
        if (buffer.length < offset + len) return;

        let payload = buffer.slice(offset, offset + len);
        if (mask) {
          const out = Buffer.allocUnsafe(payload.length);
          for (let i = 0; i < payload.length; i++) out[i] = payload[i] ^ mask[i % 4];
          payload = out;
        }
        buffer = buffer.slice(offset + len);

        if (opcode === 0x8) {
          // close
          fail(new Error("websocket closed by peer"));
          return;
        }
        if (opcode === 0x1 || opcode === 0x2) {
          const text = payload.toString("utf8");
          for (const fn of listeners.slice()) {
            try { fn(text); } catch (e) {}
          }
        }
      }
    }

    sock.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);

      if (!handshakeDone) {
        const idx = buffer.indexOf("\r\n\r\n");
        if (idx === -1) return;
        const head = buffer.slice(0, idx).toString("latin1");
        buffer = buffer.slice(idx + 4);
        if (!/^HTTP\/1\.1 101/i.test(head)) {
          return fail(new Error("devtools refused websocket upgrade"));
        }
        handshakeDone = true;
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          resolve({
            send(obj) {
              const data = Buffer.from(JSON.stringify(obj), "utf8");
              const len = data.length;
              let header;
              if (len < 126) {
                header = Buffer.from([0x81, 0x80 | len]);
              } else if (len < 65536) {
                header = Buffer.alloc(4);
                header[0] = 0x81;
                header[1] = 0x80 | 126;
                header.writeUInt16BE(len, 2);
              } else {
                header = Buffer.alloc(10);
                header[0] = 0x81;
                header[1] = 0x80 | 127;
                header.writeUInt32BE(0, 2);
                header.writeUInt32BE(len, 6);
              }
              const mask = crypto.randomBytes(4);
              const masked = Buffer.allocUnsafe(len);
              for (let i = 0; i < len; i++) masked[i] = data[i] ^ mask[i % 4];
              try { sock.write(Buffer.concat([header, mask, masked])); } catch (e) {}
            },
            onMessage(fn) { listeners.push(fn); },
            close() { try { sock.destroy(); } catch (e) {} },
          });
        }
      }
      parseFrames();
    });
  });
}

/* ------------------------------------------------------------------ *
 * CDP helpers
 * ------------------------------------------------------------------ */

function httpJson(port, path, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = require("http").request(
      { host: "127.0.0.1", port, path, method: "GET", timeout: timeoutMs || 1500 },
      (res) => {
        let body = "";
        res.setEncoding("utf8");
        res.on("data", (d) => (body += d));
        res.on("end", () => {
          try { resolve(JSON.parse(body)); } catch (e) { reject(new Error("bad json")); }
        });
      }
    );
    req.on("timeout", () => { req.destroy(); reject(new Error("timeout")); });
    req.on("error", reject);
    req.end();
  });
}

/*
 * Ask one debugging endpoint for every cookie it knows, then keep the Roblox
 * ones. Storage.getCookies needs no target/page, so it works even when the
 * browser is sitting on a blank tab.
 */
async function cookiesFromPort(port, timeoutMs) {
  const version = await httpJson(port, "/json/version", timeoutMs);
  const wsUrl = version && version.webSocketDebuggerUrl;
  if (!wsUrl) throw new Error("no webSocketDebuggerUrl");

  const ws = await wsConnect(wsUrl, timeoutMs);
  try {
    const reply = await new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error("cdp command timeout")), timeoutMs || 4000);
      ws.onMessage((text) => {
        let msg;
        try { msg = JSON.parse(text); } catch (e) { return; }
        if (msg.id === 1) {
          clearTimeout(t);
          resolve(msg);
        }
      });
      ws.send({ id: 1, method: "Storage.getCookies", params: {} });
    });

    if (reply.error) throw new Error(reply.error.message || "cdp error");
    const all = (reply.result && reply.result.cookies) || [];
    const roblox = all.filter((c) => {
      const d = String(c.domain || "").toLowerCase();
      return d === "roblox.com" || d.endsWith(".roblox.com");
    });
    return {
      browser: (version.Browser || "Chrome").replace(/\s*\/.*$/, ""),
      port,
      total: all.length,
      roblox,
      cookie: (roblox.find((c) => c.name === COOKIE_NAME) || {}).value || "",
    };
  } finally {
    ws.close();
  }
}

/*
 * Probe every configured port. Returns per-port reports so the UI can say
 * "port 9222 is not open" instead of a shrug.
 */
async function scan(options) {
  options = options || {};
  const reports = [];
  const candidates = [];
  const seen = new Set();

  for (const port of ports()) {
    try {
      if (options.origin) {
        const targets = await httpJson(port, "/json/list", 1500);
        const matchesApp = Array.isArray(targets) && targets.some((target) => {
          if (target.type !== "page" || !target.url) return false;
          try { return new URL(target.url).origin === options.origin; } catch (e) { return false; }
        });
        if (!matchesApp) {
          reports.push({ port, ok: false, error: "This browser does not have the app open." });
          continue;
        }
      }
      const r = await cookiesFromPort(port, 2500);
      reports.push({
        port,
        browser: r.browser,
        ok: true,
        cookies: r.roblox.length,
        hasRobloxSession: !!r.cookie,
      });
      if (r.cookie && !seen.has(r.cookie)) {
        seen.add(r.cookie);
        candidates.push({
          cookie: r.cookie,
          source: "chrome devtools protocol (port " + port + ")",
          browser: r.browser,
          port,
        });
      }
    } catch (e) {
      reports.push({ port, ok: false, error: e.message });
    }
  }

  return { reports, candidates };
}

function explain(reports) {
  if (!reports.length) return "No DevTools ports were probed.";
  const open = reports.filter((r) => r.ok);
  if (!open.length) {
    return (
      "No browser is listening for DevTools. Start Chrome with " +
      "--remote-debugging-port=9222, then press this again. " +
      "(See the 'Connect to Chrome directly' section in README-RUNNING.md.)"
    );
  }
  if (!open.some((r) => r.hasRobloxSession)) {
    return (
      "Connected to " + open.map((r) => r.browser + " on " + r.port).join(", ") +
      ", but it has no .ROBLOSECURITY cookie. Sign in at roblox.com in that browser."
    );
  }
  return "Found a Roblox session through the DevTools Protocol.";
}

module.exports = { scan, explain, cookiesFromPort, ports, COOKIE_NAME, DEFAULT_PORTS };
