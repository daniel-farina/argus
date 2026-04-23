#!/usr/bin/env bash
# Runs the complete DevProtector test suite:
#   1. Rust unit + integration tests
#   2. Tauri WebDriver end-to-end (via tauri-wd + selenium-webdriver)
#
# Requires: cargo, node >= 20, tauri-wd on PATH.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

GREEN='\033[0;32m'; RED='\033[0;31m'; YLW='\033[0;33m'; NC='\033[0m'
say() { printf "${YLW}==>${NC} %s\n" "$*"; }
ok()  { printf "${GREEN}OK${NC}  %s\n" "$*"; }
err() { printf "${RED}ERR${NC} %s\n" "$*"; }

say "ensuring ~/code/bad fixture is in place"
if [ ! -f "$HOME/code/bad/package.json" ]; then
  err "fixture missing at ~/code/bad - rebuild it from the repo scaffold"
  exit 1
fi

say "cargo test (rust unit + integration)"
(cd src-tauri && cargo test --test detection -- --test-threads=1)
ok  "rust tests"

say "building debug binary for WebDriver e2e"
(cd src-tauri && cargo build)
BIN="$ROOT/src-tauri/target/debug/devprotector"
if [ ! -x "$BIN" ]; then
  err "binary not built at $BIN"
  exit 1
fi

if ! command -v tauri-wd >/dev/null 2>&1; then
  say "installing tauri-webdriver-automation"
  cargo install tauri-webdriver-automation
fi

say "ensuring node deps"
if [ ! -d node_modules ]; then
  npm install --silent --no-audit --no-fund
fi

say "starting tauri-wd on port 4455"
LOGDIR="$ROOT/.test-logs"; mkdir -p "$LOGDIR"
pkill -f "tauri-wd --port 4455" 2>/dev/null || true
tauri-wd --port 4455 --log-level info >"$LOGDIR/tauri-wd.log" 2>&1 &
WD_PID=$!
trap 'kill $WD_PID 2>/dev/null || true' EXIT

# Wait for readiness.
for i in $(seq 1 40); do
  if curl -sf http://127.0.0.1:4455/status >/dev/null 2>&1; then
    break
  fi
  sleep 0.25
done

say "running e2e via selenium-webdriver"
TAURI_WD_URL="http://127.0.0.1:4455" DEVPROTECTOR_BIN="$BIN" \
  node tests/e2e.mjs

ok "all tests passed"
