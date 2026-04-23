#!/usr/bin/env bash
# Argus benchmark runner.
# - Runs all fixture assertions (malicious samples must be caught)
# - Runs the OSS noise budget against ~/code/test-repos/{express,chalk,lodash}
# - Prints a compact summary

set -euo pipefail
cd "$(dirname "$0")/.."

GRN='\033[0;32m'; RED='\033[0;31m'; YLW='\033[0;33m'; NC='\033[0m'

echo -e "${YLW}==>${NC} building scanner"
(cd src-tauri && cargo build --tests --quiet)

echo -e "${YLW}==>${NC} fixture verification"
(cd src-tauri && cargo test --test bench --quiet -- --skip oss_noise_budget_if_available 2>&1) | tail -6

echo -e "${YLW}==>${NC} OSS noise benchmark"
(cd src-tauri && DEVPROTECTOR_BENCH_OSS=1 cargo test --test bench --quiet oss_noise_budget_if_available -- --nocapture 2>&1) | grep -E "OSS|test result" || true

echo -e "${YLW}==>${NC} existing integration suite"
(cd src-tauri && cargo test --test detection --quiet 2>&1) | tail -5

echo -e "${GRN}done${NC}"
