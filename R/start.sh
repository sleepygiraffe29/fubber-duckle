#!/usr/bin/env bash
# Start the self-hosted Roblox WebClient with session support.
#
#   ./start.sh                                  port 3000
#   PORT=9000 ./start.sh                        different port
#   CHROME_PROFILE_DIR=/path/to/profile ./start.sh
#   RBX_CDP_PORT=9222 ./start.sh                DevTools port for cookie pickup
#
# This MUST be run instead of a static file server (python3 -m http.server,
# `npx serve`, VS Code Live Server). Those only serve files; the login screen
# and joining need the /api/* backend that server.js provides.

set -e
cd "$(dirname "$0")"

PORT="${PORT:-3000}"

# --- Node version -----------------------------------------------------------
# lib/cookie-detect.js uses the built-in node:sqlite module, which needs 22+.
NODE_BIN="${NODE_BIN:-node}"
if ! command -v "$NODE_BIN" >/dev/null 2>&1; then
  echo "error: node not found. Install Node.js 22 or newer." >&2
  exit 1
fi

NODE_MAJOR="$("$NODE_BIN" -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
if [ "$NODE_MAJOR" -lt 22 ]; then
  echo "error: Node $("$NODE_BIN" -v) is too old." >&2
  echo "       This build needs Node 22+ (it uses the built-in node:sqlite module)." >&2
  echo "       Install from https://nodejs.org/ or: brew install node" >&2
  exit 1
fi

# --- Port availability ------------------------------------------------------
# A stale python3 -m http.server on the same port is the most common reason
# "nothing happens" when pressing the login button.
port_busy() {
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iTCP:"$1" -sTCP:LISTEN >/dev/null 2>&1
  elif command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | grep -q ":$1 "
  else
    return 1
  fi
}

if port_busy "$PORT"; then
  echo "error: port $PORT is already in use." >&2
  if command -v lsof >/dev/null 2>&1; then
    echo "       held by:" >&2
    lsof -nP -iTCP:"$PORT" -sTCP:LISTEN | sed 's/^/         /' >&2
  fi
  echo "" >&2
  echo "       If that is a static file server (python3 -m http.server, serve," >&2
  echo "       Live Server), stop it first -- it cannot run the login backend." >&2
  echo "       Or pick another port:  PORT=9000 ./start.sh" >&2
  exit 1
fi

echo "RobloxWeb -> http://localhost:$PORT/"
echo "  login backend: /api/auth/*   join: /api/join"
echo "  log file:      server.log"
echo "  press Ctrl+C to stop"
echo ""

# --- Optional: Chrome with the DevTools port --------------------------------
# With this port open the server reads your live .ROBLOSECURITY on every join,
# so a rotated cookie is picked up automatically and macOS never prompts for
# Keychain access. Chrome must be fully quit first for the flag to take effect.
if [ "${RBX_LAUNCH_CHROME:-0}" = "1" ]; then
  echo "Launching Chrome with --remote-debugging-port=9222 ..."
  case "$(uname -s)" in
    Darwin) open -a "Google Chrome" --args --remote-debugging-port=9222 ;;
    Linux)  google-chrome --remote-debugging-port=9222 >/dev/null 2>&1 & ;;
    *)      echo "  (open Chrome manually with --remote-debugging-port=9222)" ;;
  esac
fi

# --- Run, logging to server.log, and restart if it ever exits ---------------
# A dead server is indistinguishable from a CORS failure in the browser, so
# keep it alive rather than leaving the page with "Failed to fetch" everywhere.
trap 'echo ""; echo "stopped."; exit 0' INT TERM
while true; do
  PORT="$PORT" "$NODE_BIN" server.js 2>&1 | tee -a server.log
  code="${PIPESTATUS[0]}"
  echo ""
  echo "[start.sh] server exited (code $code) -- restarting in 1s"
  echo "           (see server.log for the error)"
  sleep 1
done
