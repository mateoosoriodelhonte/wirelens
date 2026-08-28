#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
gate="$repo_root/scripts/verify-phase2.sh"
package="$repo_root/package.json"
workflow="$repo_root/.github/workflows/ci.yml"

test -x "$gate"
rg -Fq 'set -Eeuo pipefail' "$gate"

# Keep this list explicit. A Phase 2 gate must not silently lose a required lane.
for step in \
  'Check Phase 2 gate contract' \
  'Check toolchain bootstrap isolation' \
  'Build deterministic synthetic fixtures' \
  'Check fixture tests and manifests' \
  'Generate deterministic benchmark captures' \
  'Check benchmark determinism and result schema' \
  'Configure native debug build' \
  'Build native targets' \
  'Run native tests' \
  'Configure native sanitizer build' \
  'Build sanitizer targets' \
  'Run sanitizer tests' \
  'Run native Wasm API tests' \
  'Build WebAssembly' \
  'Validate JSON schema goldens' \
  'Check native/WebAssembly contract parity' \
  'Run package tests' \
  'TypeScript and project checks' \
  'Lint' \
  'Formatting' \
  'Build static web output' \
  'Chromium Playwright' \
  'Firefox Playwright' \
  'Privacy scan' \
  'Secret scan' \
  'Dependency audit (high severity)'; do
  rg -Fq "$step" "$gate"
done

for command in \
  'scripts/tests/bootstrap-local-toolchain.test.sh' \
  'pnpm --dir fixtures build' \
  'pnpm --dir fixtures test' \
  'pnpm --dir benchmarks generate' \
  'pnpm --dir benchmarks test' \
  '--preset native-debug' \
  'build/native-debug' \
  'build/native-sanitize' \
  'CMAKE_CXX_FLAGS=-fsanitize=address,undefined' \
  'ctest' \
  '--target wirelens_wasm_api_tests' \
  'bash scripts/build-wasm.sh' \
  'pnpm --dir schema test' \
  'pnpm test:parity' \
  'pnpm test' \
  'pnpm check' \
  'pnpm lint' \
  'pnpm format:check' \
  'pnpm --dir web build' \
  'pnpm test:e2e --project=chromium' \
  'pnpm test:e2e --project=firefox' \
  'bash scripts/check-privacy.sh' \
  'bash scripts/check-secrets.sh' \
  'pnpm audit --audit-level high'; do
  rg -Fq -- "$command" "$gate"
done

node --input-type=module - "$package" <<'NODE'
import { readFileSync } from 'node:fs';
const packagePath = process.argv[2];
const manifest = JSON.parse(readFileSync(packagePath, 'utf8'));
if (manifest.scripts?.['verify:phase2'] !== 'bash scripts/verify-phase2.sh') {
  throw new Error('package.json must expose the exact Phase 2 gate command');
}
NODE

rg -Fq 'run: pnpm verify:phase2' "$workflow"
rg -Fq "WIRELENS_REQUIRE_E2E: '1'" "$workflow"
rg -Fq 'web/playwright-report/' "$workflow"
rg -Fq 'web/test-results/' "$workflow"
rg -Fq 'build/' "$workflow"
