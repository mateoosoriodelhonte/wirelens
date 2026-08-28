# WireLens Phase 2 evidence

## Evidence boundary

- Measurement source HEAD: `91dba42f9a59e275ad70e4f06a49565f63689915`
- Authority: approved V1 design, Phase 2 plan, parent issue #30, and issue #31
- Host: Mac mini, Apple M4 Pro, 14 cores, 64 GiB RAM, arm64
- Operating system: macOS 26.5.2 build 25F84, Darwin 25.5.0
- Native and WebAssembly build type: Release
- Runtime: Node.js 26.7.0 and Emscripten 6.0.8
- Browser: Playwright Chromium 151.0.7922.34

The benchmark samples were collected from the measurement source HEAD. Later
review fixes change gate coverage, documentation, and C++ source formatting;
they do not change measured runtime behavior. The issue and pull request
records give the exact final evidence commit, merged HEAD, and CI run. This
avoids claiming that a checked-in file can contain its own Git commit hash.

All inputs are original deterministic synthetic PCAPs. The generators do not
open a network interface or read user capture data.

## Profiles

| Profile    |     Bytes | Packets | Purpose                                    |
| ---------- | --------: | ------: | ------------------------------------------ |
| Small      |       234 |       3 | Fast TCP smoke profile                     |
| Medium     |    71,704 |   1,024 | Representative protocol and JSON work      |
| Limit-near | 1,966,074 |  65,535 | One packet below the configured packet cap |

The limit-near profile is near the packet cap, not the 64 MiB byte cap. The
configured limits are safety boundaries. They are not performance targets.

## Median results

Native and Node WebAssembly results use 10 measured runs after 2 warmup runs.
Browser results use 3 cold production-page runs so startup and first-overview
costs remain visible. Raw samples and exact commands are in the JSON artifacts.

| Metric                                |     Small |      Medium |  Limit-near |
| ------------------------------------- | --------: | ----------: | ----------: |
| Native parse                          |  0.005 ms |    1.061 ms |   34.742 ms |
| Native parse throughput               |  Not used | 64.48 MiB/s | 53.97 MiB/s |
| Native JSON serialization             |  0.127 ms |   34.760 ms |  589.622 ms |
| Native process peak                   |  2.16 MiB |   34.58 MiB |  534.76 MiB |
| WASM module startup in Node           |  0.939 ms |    0.813 ms |    0.862 ms |
| WASM parse plus serialization         |  0.189 ms |   31.910 ms |  542.202 ms |
| WASM parse-plus-serialize throughput  |  Not used |  2.14 MiB/s |  3.46 MiB/s |
| Heap decode plus `JSON.parse` in Node |  0.047 ms |    8.195 ms |  143.004 ms |
| WASM linear-memory high-water mark    | 16.13 MiB |   27.94 MiB |  494.75 MiB |

The limit-near profile completed in native and WebAssembly runners. It uses
substantial memory because the parser owns a bounded packet model and a full
normalized JSON result. This is evidence about the safety boundary, not a
recommendation to render 65,535 packet rows.

## Browser result

| Metric                             |     Small |     Medium |    Limit-near |
| ---------------------------------- | --------: | ---------: | ------------: |
| Direct WASM module startup         |  2.900 ms |   3.100 ms |     33.000 ms |
| WASM parse plus serialization      |  0.200 ms |  32.100 ms |    553.400 ms |
| Heap decode plus `JSON.parse`      |  0.100 ms |   5.900 ms |    132.200 ms |
| Echo-worker startup handshake      |  2.800 ms |   3.000 ms |      3.200 ms |
| Warm structured-clone round trip   |  0.100 ms |  14.800 ms |    245.800 ms |
| File selection to visible overview | 95.900 ms | 242.400 ms | 10,827.800 ms |
| Filter interaction                 | 10.700 ms |  46.400 ms |  4,132.300 ms |

The worker metric is a full echo round trip after a startup handshake. It is a
conservative transport measure because the production result crosses from the
worker to the main thread once. The first-overview measurement uses the real
production Web Worker, WebAssembly module, validator, store, and Svelte view.

Browser process peak memory is `NOT_RUN`. Chromium exposes a point-in-time
estimate, not a reliable peak sampler. The limit-near browser profile includes
the real production worker, validation, 65,535-row render, completed filter,
and a separate direct WASM/worker path. Its overview and filter values include
large DOM costs. They are boundary evidence, not normal-use guidance.

## Transport decision

The medium browser run spent 5.9 ms on heap decode and `JSON.parse` and 14.8 ms
on a warm structured-clone round trip. The combined 20.7 ms is 8.5% of the
242.4 ms first-overview median. It is also below the 100 ms review trigger.

No review trigger in Decision 0001 was crossed. WireLens keeps the normal Web
Worker and the versioned normalized JSON contract. A binary or streaming
transport remains possible only after new evidence and a separate accepted
architecture decision.

## Verification inventory

The exact Phase 2 gate is:

```sh
pnpm verify:phase2
```

It fails fast and runs deterministic fixture generation, benchmark fixture and
schema tests, native and sanitizer builds, all CTest cases, the Emscripten
build, every native/WASM/golden parity fixture, all package tests, type checks,
lint, formatting, static build, Chromium and Firefox functional paths, privacy
and secret scans, and the high-severity dependency audit.

Expected integrated totals at the measurement source are:

- native CTest: 94;
- sanitizer CTest: 94;
- package tests: 171 (16 benchmark, 12 fixture, 22 schema, 121 web);
- functional Playwright: 14 (7 Chromium and 7 Firefox);
- opt-in Chromium benchmark: 1.

The final issue and pull request evidence must mark each gate `PASS`, `FAIL`,
`NOT_RUN`, or `UNKNOWN`. A low-severity dependency advisory remains below the
configured high-severity failure threshold.

## Artifacts

| Artifact                                           | SHA-256                                                            |
| -------------------------------------------------- | ------------------------------------------------------------------ |
| `artifacts/phase-2/benchmark-native.json`          | `0380a393da981fd92670f2bda1e0d438cc4e59ab8d8883b7249595ee72203356` |
| `artifacts/phase-2/benchmark-wasm.json`            | `c959742d26c2b94043303841d1d0446f325205d74aeea31120443f976381409b` |
| `artifacts/phase-2/benchmark-browser.json`         | `95d27d4baa9859d15b0580a9e1b4d140768ab526ca0dde3cf2bec55a0a4a2b8b` |
| `artifacts/phase-2/dns-exchanges.png`              | `ecd0a2d4c49e4a7cf984fc8bb749174d51c9d8303ea6e5b3dab712c574e18894` |
| `artifacts/phase-2/inspection-tools-highlight.png` | `7fad989ba0992402ecfe3076f95de7a1e4f7142b0b05c98f2ab1b22776244744` |
| `artifacts/phase-2/inspection-tools-evidence.png`  | `bd98fcde8d7a2363417bc926653f9f5191ac041c401a7a54140936896fbd9977` |

## Remaining V1 work

- add the specification's named normalized-JSON size cap, boundary test, and
  typed failure; the limit-near benchmark produced 99,694,542 JSON bytes, and
  its artifact records a 534.76 MiB median native process peak;
- improve large-capture presentation without changing parser safety limits;
- complete endpoint/protocol distribution, capture timeline, and latency views;
- add sanitized Markdown/JSON export and optional stable-label anonymization;
- complete accessibility and usability work with real-browser tests;
- add adversarial corpus tests, fuzzing, and available static analysis;
- verify the static GitHub Pages build with the synthetic browser path, then
  complete the separately authorized `v1.0.0` release work;
- revisit transport only if later reproducible evidence crosses Decision 0001.

Deployment, a tag, and a release are outside Phase 2.
