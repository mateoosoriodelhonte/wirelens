#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
scanner="$repo_root/scripts/check-privacy.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/wirelens-privacy-test.XXXXXX")
trap 'rm -rf "$test_root"' EXIT

safe_source="$test_root/safe"
unsafe_source="$test_root/unsafe"
mkdir -p "$safe_source" "$unsafe_source"
printf '<p>{captureSummary}</p>\n' >"$safe_source/App.svelte"
printf '<p>{@html untrustedCaptureText}</p>\n' >"$unsafe_source/App.svelte"

WIRELENS_WEB_SOURCE="$safe_source" bash "$scanner" >/dev/null

unsafe_output="$test_root/unsafe-output"
if WIRELENS_WEB_SOURCE="$unsafe_source" bash "$scanner" >"$unsafe_output" 2>&1; then
  printf 'Privacy scan regression: FAIL (unsafe Svelte HTML directive was accepted)\n' >&2
  exit 1
fi
rg -Fq '{@html untrustedCaptureText}' "$unsafe_output"

printf 'Privacy scan regression: PASS\n'
