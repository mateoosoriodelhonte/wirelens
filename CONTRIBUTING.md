# Contributing to WireLens

## Before you change code

Read the accepted design and Phase 1 plan in `docs/superpowers/`. Keep the
local-first boundary intact. Do not add live capture, packet transmission,
replay, scanning, probing, decryption, a backend, telemetry, analytics, or
capture upload without a new approved design.

Use a short feature branch and keep commits small and focused.

## Local setup

```sh
./scripts/bootstrap-local-toolchain.sh
pnpm install --frozen-lockfile
```

For native and WebAssembly work, install Emscripten 6.0.8 in `.tools/emsdk`.
The CI workflow is the reference for the pinned toolchain setup. Do not use a
global CMake or Ninja binary when checking the full gate.

## Checks

Run the complete gate before review:

```sh
pnpm verify:phase1
```

The gate rebuilds the deterministic fixture, native targets, WebAssembly, and
static output. It runs native tests, package tests, native/WebAssembly/golden
contract parity, TypeScript checks, lint, formatting, privacy and secret scans,
and a high-severity dependency audit. Playwright is marked `NOT_RUN` when Task
10's dependency and test are not present.

If a required tool is missing, report the exact command and state. Do not hide a
failed or skipped check. Do not commit build output, `.tools`, test reports,
environment files, keys, credentials, or capture data.

## Pull requests

Explain the user-visible result, list changed paths, and include the exact
checks that passed, failed, or were not run. Keep unrelated cleanup out of the
pull request. Do not push, merge, deploy, or publish from an implementation
task unless the owner gives separate approval.
