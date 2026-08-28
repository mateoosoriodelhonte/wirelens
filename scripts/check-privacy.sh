#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd -P)
web_source=${WIRELENS_WEB_SOURCE:-"$repo_root/web/src"}

if [[ ! -d "$web_source" ]]; then
  printf 'Privacy scan: FAIL (missing web/src)\n' >&2
  exit 1
fi

# WireLens has no capture-related network, browser persistence, or unsafe HTML
# path. Same-origin WebAssembly loading is generated outside web/src.
patterns='fetch\(|XMLHttpRequest|sendBeacon|WebSocket|EventSource|\{@html|innerHTML|localStorage|sessionStorage|indexedDB|document\.cookie'
if rg -n --regexp "$patterns" "$web_source"; then
  printf 'Privacy scan: FAIL (browser network, persistence, or unsafe rendering API found)\n' >&2
  exit 1
fi

printf 'Privacy scan: PASS (web/src has no capture upload, browser persistence, or unsafe HTML path)\n'
