#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$repo_root"

tool_dir=${WIRELENS_TOOL_DIR:-"$repo_root/.tools"}
cmake="$tool_dir/venv/bin/cmake"
ninja="$tool_dir/venv/bin/ninja"
ctest="$tool_dir/venv/bin/ctest"

if [[ ! -x "$cmake" || ! -x "$ninja" || ! -x "$ctest" ]]; then
  printf 'Phase 1 verification: FAIL (local CMake/Ninja missing; run scripts/bootstrap-local-toolchain.sh)\n' >&2
  exit 1
fi
if ! command -v rg >/dev/null 2>&1; then
  printf 'Phase 1 verification: FAIL (ripgrep is required for privacy, secret, and bootstrap checks)\n' >&2
  exit 1
fi

export PATH="$tool_dir/venv/bin:$PATH"

run_step() {
  local name=$1
  shift
  printf '\n== %s ==\n' "$name"
  "$@"
}

run_step 'Build synthetic fixture' pnpm --dir fixtures build
run_step 'Check toolchain bootstrap isolation' bash scripts/tests/bootstrap-local-toolchain.test.sh
run_step 'Configure native debug build' "$cmake" --preset native-debug --fresh
run_step 'Build native targets' "$cmake" --build --preset native-debug --parallel
run_step 'Run native tests' "$ctest" --test-dir build/native-debug --output-on-failure
run_step 'Build WebAssembly' bash scripts/build-wasm.sh
run_step 'Build static web output' pnpm --dir web build
run_step 'Run package tests' pnpm test
run_step 'Check native/WebAssembly contract parity' pnpm test:parity
run_step 'TypeScript and project checks' pnpm check
run_step 'Lint' pnpm lint
run_step 'Formatting' pnpm format:check
run_step 'Privacy scan' bash scripts/check-privacy.sh
run_step 'Secret scan' bash scripts/check-secrets.sh
run_step 'Dependency audit (high severity)' pnpm audit --audit-level high

has_e2e_script=$(node --input-type=module -e \
  "import { readFileSync } from 'node:fs'; const p=JSON.parse(readFileSync('web/package.json','utf8')); process.stdout.write(typeof p.scripts?.['test:e2e'] === 'string' ? 'yes' : 'no');")
playwright_bin="$repo_root/web/node_modules/.bin/playwright"
root_playwright_bin="$repo_root/node_modules/.bin/playwright"
if [[ "$has_e2e_script" == yes && ( -x "$playwright_bin" || -x "$root_playwright_bin" ) ]]; then
  run_step 'Chromium and Firefox Playwright' pnpm test:e2e
else
  printf '\n== Chromium and Firefox Playwright ==\n'
  printf 'Playwright: NOT_RUN (web test:e2e script or dependency is absent; Task 10 must add it)\n'
  if [[ ${WIRELENS_REQUIRE_E2E:-0} == 1 ]]; then
    printf 'Phase 1 verification: FAIL (E2E is required in this environment)\n' >&2
    exit 1
  fi
fi

printf '\nPhase 1 verification: PASS\n'
