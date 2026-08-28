# WireLens benchmark framework

This directory contains deterministic, local-only performance measurements for
Phase 2. The generator creates classic little-endian microsecond PCAP files
from fixed bytes. It does not open a network socket or read a capture supplied
by a user.

## Profiles

| Profile      | Packets | Purpose                                             |
| ------------ | ------: | --------------------------------------------------- |
| `small`      |       3 | Fast smoke measurement with TCP protocol facts      |
| `medium`     |   1,024 | Representative protocol and JSON workload           |
| `limit-near` |  65,535 | One packet below the configured 65,536 packet limit |

The limit-near profile uses minimal Ethernet/ARP frames. This keeps its
normalized JSON bounded while still exercising packet-count handling. It is a
configured boundary fixture, not a performance claim.

## Native measurements

Build the native runner with the repository's pinned CMake and Ninja tools:

```sh
cmake --preset native-release
cmake --build build/native-release --target wirelens_benchmark_native
WIRELENS_BENCHMARK_RUNS=10 WIRELENS_BENCHMARK_WARMUP=2 \
  pnpm --dir benchmarks run-native -- \
  ./build/native-release/benchmarks/wirelens_benchmark_native \
  results/native.json
```

The runner measures parse and JSON serialization in separate timers. Warmup
runs execute both operations. Native peak memory uses `getrusage` where the
platform provides it; unsupported memory measurements have an empty sample
list and `supported: false`.

## Browser and WebAssembly measurements

Run the WebAssembly runner against the built Emscripten module. This path
measures all three profiles in Node and does not send limit-near bytes through
Playwright:

```sh
WIRELENS_BENCHMARK_RUNS=10 WIRELENS_BENCHMARK_WARMUP=2 \
  pnpm --dir benchmarks run-wasm -- \
  ../web/static/wasm/wirelens.js results/wasm.json
```

`web/e2e/phase-2/benchmark-performance.spec.ts` measures module startup,
WASM parse-plus-serialization, heap-to-JavaScript decode and `JSON.parse`, an
echo-worker startup handshake, a warm structured-clone round trip, production
file-to-overview time, and filter latency. It runs only the small and medium
profiles in a browser. The
limit-near record is present with browser/WASM values unset, because passing a
multi-megabyte array through Playwright and rendering 65,535 rows would not be
a reliable browser measurement. Browser memory remains explicitly unsupported
because the available API is a point-in-time snapshot, not a peak sampler.
The Node WASM runner also records `wasmLinearMemoryPeakBytes`: the
post-parse `HEAPU8.byteLength` from a fresh module for each run. This is a
WASM linear-memory high-water mark, not process memory.
The browser spec is opt-in and Chromium-only:

```sh
WIRELENS_BENCHMARK=1 pnpm --dir web test:e2e --project=chromium \
  e2e/phase-2/benchmark-performance.spec.ts
```

Every result uses [`result.schema.json`](result.schema.json). The validator
requires exact metadata, raw samples, recomputed medians, and one each of the
three profiles. Results are measurement evidence. They do not change the
64 MiB or 65,536-packet safety limits and do not authorize a transport change.
