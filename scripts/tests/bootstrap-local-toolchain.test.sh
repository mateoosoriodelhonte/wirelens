#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
test_root=$(mktemp -d)

cleanup() {
  rm -rf "$test_root"
}
trap cleanup EXIT

WIRELENS_TOOL_DIR="$test_root/tools" \
  "$repo_root/scripts/bootstrap-local-toolchain.sh" --print-paths > "$test_root/out"

rg -F "$test_root/tools" "$test_root/out"
rg -F "Clang format: $test_root/tools/venv/bin/clang-format" "$test_root/out"
if rg -F '/opt/homebrew' "$test_root/out"; then
  exit 1
fi
