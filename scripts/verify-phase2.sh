#!/usr/bin/env bash
set -Eeuo pipefail

repo_root=$(cd "$(dirname "$0")/.." && pwd -P)
cd "$repo_root"

tool_dir=${WIRELENS_TOOL_DIR:-"$repo_root/.tools"}
cmake="$tool_dir/venv/bin/cmake"
ninja="$tool_dir/venv/bin/ninja"
ctest="$tool_dir/venv/bin/ctest"
clang_format="$tool_dir/venv/bin/clang-format"

if [[ ! -x "$cmake" || ! -x "$ninja" || ! -x "$ctest" || ! -x "$clang_format" ]]; then
  printf 'Phase 2 verification: FAIL (local CMake/Ninja/clang-format missing; run scripts/bootstrap-local-toolchain.sh)\n' >&2
  exit 1
fi
if ! command -v rg >/dev/null 2>&1; then
  printf 'Phase 2 verification: FAIL (ripgrep is required for privacy, secret, and bootstrap checks)\n' >&2
  exit 1
fi

export PATH="$tool_dir/venv/bin:$PATH"

run_step() {
  local name=$1
  shift
  printf '\n== %s ==\n' "$name"
  "$@"
}

check_cpp_format() {
  git ls-files -z '*.cpp' '*.hpp' '*.h' | xargs -0 "$clang_format" --dry-run --Werror
}

run_step 'Check Phase 2 gate contract' bash scripts/tests/verify-phase2.test.sh
run_step 'Check toolchain bootstrap isolation' bash scripts/tests/bootstrap-local-toolchain.test.sh
run_step 'Build deterministic synthetic fixtures' pnpm --dir fixtures build
run_step 'Check fixture tests and manifests' pnpm --dir fixtures test
run_step 'Check generated fixture determinism' git diff --exit-code -- fixtures/generated fixtures/manifests
run_step 'Generate deterministic benchmark captures' pnpm --dir benchmarks generate
run_step 'Check benchmark determinism and result schema' pnpm --dir benchmarks test

run_step 'Configure native debug build' "$cmake" --preset native-debug --fresh
run_step 'Build native targets' "$cmake" --build --preset native-debug --parallel
run_step 'Run native tests' "$ctest" --test-dir build/native-debug --output-on-failure

sanitizer_build_dir="$repo_root/build/native-sanitize"
run_step 'Configure native sanitizer build' "$cmake" -S "$repo_root" -B "$sanitizer_build_dir" -G Ninja \
  --fresh \
  -DCMAKE_BUILD_TYPE=Debug \
  -DWIRELENS_BUILD_TESTS=ON \
  -DWIRELENS_WARNINGS_AS_ERRORS=ON \
  -DCMAKE_CXX_FLAGS=-fsanitize=address,undefined \
  -DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined
run_step 'Build sanitizer targets' "$cmake" --build "$sanitizer_build_dir" --parallel
asan_options=detect_leaks=1:halt_on_error=1
if [[ "$(uname -s)" == Darwin ]]; then
  # Apple Clang's AddressSanitizer does not implement LeakSanitizer.
  asan_options=detect_leaks=0:halt_on_error=1
fi
run_step 'Run sanitizer tests' env ASAN_OPTIONS="$asan_options" UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$ctest" --test-dir "$sanitizer_build_dir" --output-on-failure

run_step 'Run native Wasm API tests' "$cmake" --build --preset native-debug --target wirelens_wasm_api_tests
run_step 'Run native Wasm API CTest' "$ctest" --test-dir build/native-debug --output-on-failure -R '^WasmApi$'
run_step 'Build WebAssembly' bash scripts/build-wasm.sh

run_step 'Validate JSON schema goldens' pnpm --dir schema test
run_step 'Check native/WebAssembly contract parity' pnpm test:parity
run_step 'Run package tests' pnpm test
run_step 'TypeScript and project checks' pnpm check
run_step 'Lint' pnpm lint
run_step 'Formatting' pnpm format:check
run_step 'C++ formatting' check_cpp_format
run_step 'Build static web output' pnpm --dir web build

playwright_bin="$repo_root/web/node_modules/.bin/playwright"
if [[ ! -x "$playwright_bin" ]]; then
  printf 'Phase 2 verification: FAIL (web Playwright dependency is missing; run pnpm install --frozen-lockfile)\n' >&2
  exit 1
fi
run_step 'Chromium Playwright' pnpm test:e2e --project=chromium
run_step 'Firefox Playwright' pnpm test:e2e --project=firefox

run_step 'Check privacy scan rules' bash scripts/tests/check-privacy.test.sh
run_step 'Privacy scan' bash scripts/check-privacy.sh
run_step 'Secret scan' bash scripts/check-secrets.sh
run_step 'Dependency audit (high severity)' pnpm audit --audit-level high

printf '\nPhase 2 verification: PASS\n'
