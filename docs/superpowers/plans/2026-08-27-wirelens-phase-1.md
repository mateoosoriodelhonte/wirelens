# WireLens Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Workers must not spawn subagents.

**Goal:** Prove the complete WireLens architecture with one synthetic TCP handshake: C++20 parser, normalized JSON, native CLI, WebAssembly, Web Worker, Svelte UI, and Chromium verification.

**Architecture:** A safe C++20 core parses one bounded capture into a transport-neutral domain model. The CLI and a small Emscripten C ABI serialize the same normalized JSON contract. A normal Web Worker owns capture bytes and WebAssembly; the SvelteKit static UI consumes only validated contract data.

**Tech Stack:** C++20, CMake 4.4.3, Catch2 3.16.0, nlohmann/json 3.12.0, Emscripten 6.0.8, Svelte 5.56.10, SvelteKit 2.70.3, TypeScript 7.0.2, Vite 8.2.2, pnpm 11.24.0, Ajv 8.20.0, Vitest 4.1.11, Playwright 1.62.1.

**Spec:** `docs/superpowers/specs/2026-08-27-wirelens-v1-design.md`

## Global Constraints

- The accepted specification is the product and architecture authority.
- Modify only `/Users/studio3/Code/Personal/wirelens`, its isolated worktrees, and normal WireLens build or cache directories.
- C++ parser reads use checked `std::span<const std::byte>` operations. Do not use unchecked parser pointer arithmetic.
- Treat capture bytes as hostile. Return typed parse errors and enforce a 64 MiB Phase 1 input cap.
- Do not add live capture, packet transmission, replay, scanning, probing, decryption, root access, a backend, telemetry, analytics, or capture upload.
- Do not place raw packet bytes in normalized JSON.
- Use `schema: "wirelens.capture"` and `contractVersion: "1.0.0"` verbatim.
- Store absolute and relative nanosecond times as decimal strings so JavaScript never loses integer precision.
- The native CLI and WebAssembly build must serialize the same capture document for the same fixture.
- The browser must transfer the selected `ArrayBuffer` to a normal Web Worker and make one bounded copy into WebAssembly memory.
- The worker owns the WebAssembly result handle and releases it on replacement, cancellation, error, and termination.
- The Svelte UI must be static, accessible, keyboard usable, responsive, and free of React.
- All fixtures must be original, deterministic, synthetic data. The builder must not open an interface or send a packet.
- Use test-first red-green-refactor cycles for parser, contract, worker, and UI behavior. Record the failing and passing commands in each worker report.
- Use the repository-local Git identity `Mateo Osorio Delhonte <259801526+mateoosoriodelhonte@users.noreply.github.com>`.
- Do not push implementation directly to `main`. Use the Phase 1 issue, isolated branches, pull request, and green CI.

## Trust Boundaries and Abuse Cases

| Boundary | Abuse case | Required control |
| --- | --- | --- |
| File to worker | Oversized or deceptive file | 64 MiB guard before transfer and magic-byte validation in C++ |
| Worker to C++ | Truncated lengths and offset overflow | Checked reader, subtraction-based bounds checks, typed errors |
| C++ to TypeScript | Malformed or incompatible JSON | JSON parse plus schema/version validation before state update |
| Capture text to DOM | Hostile protocol text used as markup | Svelte text interpolation only; no `{@html}` or `innerHTML` |
| Active result handle | Leaked capture memory | Explicit release and worker termination tests |
| Export | Sensitive packet content disclosure | Phase 1 exports no raw bytes; later export uses sanitized model only |

## File Ownership Map

The first parallel round starts after Task 1. Each lane uses a separate Git worktree and must stay inside its owned paths.

| Lane | Owned paths | Must not edit |
| --- | --- | --- |
| Contract and fixture | `schema/**`, `fixtures/**` | `core/**`, `cli/**`, `wasm/**`, `web/**`, root build files |
| C++ core and CLI | `core/**`, `cli/**` | `schema/**`, `fixtures/**`, `wasm/**`, `web/**`, root build files |
| Frontend presentation | `web/**` except `web/src/lib/worker/**` and `web/src/lib/wasm/**` | C++, schema, fixtures, root build files |
| Integration lead | Root files, `wasm/**`, worker/wasm paths, CI, docs | May reconcile imported lane files after lane commits |

## Shared Interfaces

### Capture document

```ts
export interface CaptureDocument {
  schema: 'wirelens.capture';
  contractVersion: '1.0.0';
  capture: {
    format: 'pcap';
    timestampResolution: 'microseconds' | 'nanoseconds';
    packetCount: number;
    capturedBytes: number;
    originalBytes: number;
    startTimestampNs: string | null;
    endTimestampNs: string | null;
    durationNs: string;
  };
  endpoints: Endpoint[];
  packets: Packet[];
  flows: TcpFlow[];
  diagnostics: ParseDiagnostic[];
}
```

`Packet.id` uses `packet-<one-based-number>`. `TcpFlow.id` uses `tcp-flow-<one-based-number>`. Protocol names use uppercase strings: `ETHERNET`, `IPV4`, and `TCP`.

### Parse error

```ts
export interface ParseError {
  code:
    | 'FILE_TOO_LARGE'
    | 'TRUNCATED_GLOBAL_HEADER'
    | 'UNSUPPORTED_MAGIC'
    | 'UNSUPPORTED_VERSION'
    | 'UNSUPPORTED_LINK_TYPE'
    | 'TRUNCATED_PACKET_HEADER'
    | 'INVALID_PACKET_LENGTH'
    | 'TRUNCATED_PACKET_DATA';
  message: string;
  captureOffset: number | null;
  packetNumber: number | null;
}
```

### Synthetic handshake

The fixture uses documentation-only addresses and deterministic values:

```text
Client MAC: 02:00:00:00:00:01
Server MAC: 02:00:00:00:00:02
Client IPv4: 192.0.2.10
Server IPv4: 198.51.100.20
Client port: 51515
Server port: 443
Client initial sequence: 1000
Server initial sequence: 5000
Timestamps: 1.000000 s, 1.010000 s, 1.020000 s
Frames: SYN, SYN+ACK, ACK
Frame length: 54 bytes each
```

---

### Task 1: Repository and Toolchain Foundation

**Files:**

- Create: `.gitignore`
- Create: `.editorconfig`
- Create: `.clang-format`
- Create: `.prettierrc.json`
- Create: `LICENSE`
- Create: `CMakeLists.txt`
- Create: `CMakePresets.json`
- Create: `cmake/Dependencies.cmake`
- Create: `package.json`
- Create: `pnpm-workspace.yaml`
- Create: `scripts/bootstrap-local-toolchain.sh`
- Create: `scripts/check-secrets.sh`
- Create: `scripts/tests/bootstrap-local-toolchain.test.sh`
- Modify: `docs/superpowers/specs/2026-08-27-wirelens-v1-design.md`

**Interfaces:**

- Produces `wirelens_core`, `wirelens_cli`, and `wirelens_tests` CMake targets through child directories when they exist.
- Produces root commands `pnpm format:check`, `pnpm test`, `pnpm check`, `pnpm build`, and `pnpm test:e2e`.
- Keeps `.tools/`, `.worktrees/`, `.superpowers/`, build output, dependency output, environment files, keys, and Playwright artifacts out of Git.

- [ ] **Step 1: Write a failing bootstrap isolation test**

```bash
#!/usr/bin/env bash
set -euo pipefail
repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT
WIRELENS_TOOL_DIR="$test_root/tools" "$repo_root/scripts/bootstrap-local-toolchain.sh" --print-paths > "$test_root/out"
rg -F "$test_root/tools" "$test_root/out"
if rg -F '/opt/homebrew' "$test_root/out"; then exit 1; fi
```

- [ ] **Step 2: Run the test and confirm the script is missing**

Run: `bash scripts/tests/bootstrap-local-toolchain.test.sh`

Expected: FAIL because `scripts/bootstrap-local-toolchain.sh` does not exist.

- [ ] **Step 3: Add repository-safe bootstrap and build configuration**

The bootstrap script must use `${WIRELENS_TOOL_DIR:-$repo_root/.tools}`. It creates a Python virtual environment there and installs `cmake==4.4.3` and `ninja==1.13.0` only inside that directory. `--print-paths` prints planned paths without installing.

Root CMake must set C++20, disable compiler extensions, include `cmake/Dependencies.cmake`, and add existing `core`, `cli`, and `wasm` child directories. `Dependencies.cmake` must pin Catch2 `v3.16.0` and nlohmann/json `v3.12.0` with `FetchContent`.

- [ ] **Step 4: Run foundation checks**

Run:

```bash
bash scripts/tests/bootstrap-local-toolchain.test.sh
git check-ignore .tools .worktrees .superpowers web/node_modules web/build
```

Expected: PASS and every generated path is ignored.

- [ ] **Step 5: Commit**

```bash
git add .gitignore .editorconfig .clang-format .prettierrc.json LICENSE CMakeLists.txt CMakePresets.json cmake package.json pnpm-workspace.yaml scripts docs/superpowers/specs/2026-08-27-wirelens-v1-design.md
git commit -m "chore: establish WireLens build foundation"
```

### Task 2: Versioned Contract and Synthetic Fixture

**Lane:** Contract and fixture worktree.

**Files:**

- Create: `schema/package.json`
- Create: `schema/tsconfig.json`
- Create: `schema/capture.schema.json`
- Create: `schema/src/capture.ts`
- Create: `schema/src/validate.ts`
- Create: `schema/src/index.ts`
- Create: `schema/src/validate.test.ts`
- Create: `fixtures/package.json`
- Create: `fixtures/src/checksum.ts`
- Create: `fixtures/src/build-handshake.ts`
- Create: `fixtures/src/build-handshake.test.ts`
- Create: `fixtures/generated/tcp-handshake.pcap`
- Create: `fixtures/manifests/tcp-handshake.json`
- Create: `fixtures/README.md`

**Interfaces:**

- Produces `CaptureDocument`, `ParseError`, `Packet`, `ProtocolLayer`, `ProtocolField`, `Endpoint`, and `TcpFlow` TypeScript types.
- Produces `validateCaptureDocument(value: unknown): CaptureDocument` with a typed `ContractValidationError`.
- Produces a 234-byte classic PCAP: 24-byte header plus three `(16 + 54)` byte records.

- [ ] **Step 1: Write failing contract tests**

```ts
import { describe, expect, it } from 'vitest';
import { validateCaptureDocument } from './validate.js';

describe('validateCaptureDocument', () => {
  it('rejects an unknown contract major version', () => {
    expect(() => validateCaptureDocument({ schema: 'wirelens.capture', contractVersion: '2.0.0' }))
      .toThrow(/contractVersion/);
  });

  it('accepts the minimal Phase 1 document', () => {
    const value = {
      schema: 'wirelens.capture', contractVersion: '1.0.0',
      capture: { format: 'pcap', timestampResolution: 'microseconds', packetCount: 0,
        capturedBytes: 0, originalBytes: 0, startTimestampNs: null,
        endTimestampNs: null, durationNs: '0' },
      endpoints: [], packets: [], flows: [], diagnostics: []
    };
    expect(validateCaptureDocument(value)).toEqual(value);
  });
});
```

- [ ] **Step 2: Run contract tests and confirm the validator is missing**

Run: `pnpm --dir schema install --lockfile=false && pnpm --dir schema test`

Expected: FAIL because `validate.ts` does not exist.

- [ ] **Step 3: Add schema, types, and Ajv validation**

The JSON Schema must use draft 2020-12, permit unknown optional object fields for minor-version compatibility, require every known field, use the exact root identifiers, use decimal-string time patterns `^(0|[1-9][0-9]*)$`, and use non-negative integer byte ranges. Closed enums reject unknown values. Protocol field values are strings. A field byte range contains `captureOffset`, `packetOffset`, and `length`.

- [ ] **Step 4: Write the fixture-size and packet-value test**

```ts
it('builds the exact three-packet handshake capture', () => {
  const bytes = buildTcpHandshakePcap();
  expect(bytes.byteLength).toBe(234);
  expect([...bytes.slice(0, 4)]).toEqual([0xd4, 0xc3, 0xb2, 0xa1]);
  expect(new DataView(bytes.buffer).getUint32(24 + 8, true)).toBe(54);
});
```

- [ ] **Step 5: Run the fixture test and confirm the builder is missing**

Run: `pnpm --dir fixtures install --lockfile=false && pnpm --dir fixtures test`

Expected: FAIL because `buildTcpHandshakePcap` does not exist.

- [ ] **Step 6: Implement deterministic fixture construction**

Write Ethernet, IPv4, and TCP bytes directly into fixed-size `Uint8Array` values. Compute the IPv4 header checksum and TCP pseudo-header checksum. Write the PCAP global and record headers in little-endian form. Do not use a packet-capture or packet-transmission library.

- [ ] **Step 7: Generate and verify artifacts**

Run:

```bash
pnpm --dir schema test
pnpm --dir fixtures test
pnpm --dir fixtures build
shasum -a 256 fixtures/generated/tcp-handshake.pcap
```

Expected fixture SHA-256 is recorded in `fixtures/manifests/tcp-handshake.json`. A second build must produce the same hash.

- [ ] **Step 8: Commit**

```bash
git add schema fixtures
git commit -m "feat: define capture contract and handshake fixture"
```

### Task 3: C++ Parser, Flow Reconstruction, Serialization, and CLI

**Lane:** C++ core and CLI worktree.

**Files:**

- Create: `core/CMakeLists.txt`
- Create: `core/include/wirelens/byte_reader.hpp`
- Create: `core/include/wirelens/error.hpp`
- Create: `core/include/wirelens/model.hpp`
- Create: `core/include/wirelens/parser.hpp`
- Create: `core/include/wirelens/serialize.hpp`
- Create: `core/src/byte_reader.cpp`
- Create: `core/src/pcap_parser.cpp`
- Create: `core/src/ethernet_parser.cpp`
- Create: `core/src/ipv4_parser.cpp`
- Create: `core/src/tcp_parser.cpp`
- Create: `core/src/flow_builder.cpp`
- Create: `core/src/serialize.cpp`
- Create: `core/tests/CMakeLists.txt`
- Create: `core/tests/fixture_builder.hpp`
- Create: `core/tests/byte_reader_test.cpp`
- Create: `core/tests/pcap_parser_test.cpp`
- Create: `core/tests/protocol_parser_test.cpp`
- Create: `core/tests/flow_builder_test.cpp`
- Create: `core/tests/serialization_test.cpp`
- Create: `cli/CMakeLists.txt`
- Create: `cli/main.cpp`
- Create: `cli/tests/cli_test.cpp`

**Interfaces:**

```cpp
namespace wirelens {
constexpr std::size_t kMaxCaptureBytes = 64U * 1024U * 1024U;
using ParseResult = std::variant<CaptureDocument, ParseError>;
[[nodiscard]] ParseResult parse_capture(std::span<const std::byte> bytes);
[[nodiscard]] std::string serialize_capture(const CaptureDocument& capture);
[[nodiscard]] std::string format_summary(const CaptureDocument& capture);
}
```

`ByteReader` exposes checked `read_u8`, `read_u16_le`, `read_u16_be`, `read_u32_le`, `read_u32_be`, `read_span`, `skip`, `position`, and `remaining`. It checks `length <= remaining()` before addition so offset arithmetic cannot overflow.

- [ ] **Step 1: Write bounded-reader failure tests**

```cpp
TEST_CASE("ByteReader refuses reads beyond the remaining span") {
  const std::array<std::byte, 1> bytes{std::byte{0x42}};
  wirelens::ByteReader reader(bytes);
  REQUIRE(reader.read_u8() == 0x42);
  REQUIRE_FALSE(reader.read_u8().has_value());
  REQUIRE(reader.position() == 1);
}
```

- [ ] **Step 2: Run the focused test and confirm it fails**

Run: `cmake --build --preset native-debug --target wirelens_tests && ctest --preset native-debug -R ByteReader --output-on-failure`

Expected: FAIL because `ByteReader` does not exist.

- [ ] **Step 3: Implement the minimal checked reader**

Use `std::span` subspans and `std::optional`. A failed read does not change position.

- [ ] **Step 4: Add PCAP red tests**

Cover a truncated global header, unknown magic, unsupported link type, truncated record header, `captured_length > original_length`, captured length larger than remaining input, valid empty capture, and the exact three-record in-memory fixture.

- [ ] **Step 5: Run and observe the parser failures**

Run: `ctest --preset native-debug -R 'Pcap|Malformed' --output-on-failure`

Expected: FAIL because `parse_capture` has no PCAP implementation.

- [ ] **Step 6: Implement safe PCAP record parsing**

Support all four classic magic byte sequences. Accept version 2.4 and link type 1. Convert timestamps to decimal nanosecond strings with checked 64-bit arithmetic. Reject the file before record parsing when it exceeds `kMaxCaptureBytes`.

- [ ] **Step 7: Add protocol-layer red tests**

Assert exact MAC addresses, IPv4 addresses, TTL 64, TCP ports, sequence numbers, acknowledgment numbers, flags, summaries, and field byte ranges for all three fixture packets. Add one truncation test at every layer boundary.

- [ ] **Step 8: Implement Ethernet II, IPv4, and TCP decoders**

Decode only within each enclosing payload length. Store field values as strings and store exact field byte ranges. Unknown EtherType or IPv4 protocol stays a valid outer layer with no false inner layer.

- [ ] **Step 9: Add flow-state red tests**

```cpp
REQUIRE(flow.client.address == "192.0.2.10");
REQUIRE(flow.server.address == "198.51.100.20");
REQUIRE(flow.handshake == wirelens::HandshakeState::complete);
REQUIRE(flow.events.size() == 3);
REQUIRE(flow.events[0].label == "SYN");
REQUIRE(flow.events[1].label == "SYN + ACK");
REQUIRE(flow.events[2].label == "ACK");
```

- [ ] **Step 10: Implement initial TCP flow reconstruction**

Use SYN without ACK to set client direction. Verify the SYN-ACK reverses endpoints and acknowledges client sequence plus one. Verify the final ACK acknowledges server sequence plus one. Otherwise mark the handshake partial.

- [ ] **Step 11: Add serialization and CLI red tests**

Serialization must contain the exact root identifiers, three packets, one flow, no raw-byte or payload field, and stable ordering. CLI tests must cover missing path, malformed capture exit code 2, summary output, and `--json` output.

- [ ] **Step 12: Implement deterministic JSON and CLI**

Use nlohmann/json only in `serialize.cpp`. `wirelens capture.pcap` prints packet count, duration, TCP connection count, and handshake state. `wirelens capture.pcap --json` prints the capture document followed by one newline.

- [ ] **Step 13: Run the C++ and CLI gates**

Run:

```bash
cmake --preset native-debug
cmake --build --preset native-debug
ctest --preset native-debug --output-on-failure
```

Expected: all tests pass with no compiler warnings.

- [ ] **Step 14: Commit**

```bash
git add core cli
git commit -m "feat: parse TCP handshake captures in C++"
```

### Task 4: Svelte Presentation Slice

**Lane:** Frontend presentation worktree.

**Files:**

- Create: `web/package.json`
- Create: `web/svelte.config.js`
- Create: `web/vite.config.ts`
- Create: `web/tsconfig.json`
- Create: `web/src/app.html`
- Create: `web/src/app.css`
- Create: `web/src/routes/+layout.ts`
- Create: `web/src/routes/+page.svelte`
- Create: `web/src/lib/model.ts`
- Create: `web/src/lib/demo-document.ts`
- Create: `web/src/lib/components/CapturePicker.svelte`
- Create: `web/src/lib/components/CaptureOverview.svelte`
- Create: `web/src/lib/components/ConversationList.svelte`
- Create: `web/src/lib/components/TcpSequence.svelte`
- Create: `web/src/lib/components/PacketTable.svelte`
- Create: `web/src/lib/components/PacketDetails.svelte`
- Create: one colocated `.test.ts` file for each component listed above.

**Interfaces:**

- Components receive immutable `CaptureDocument` data or selected entity values as props.
- `CapturePicker` dispatches a `File` through `onFile(file: File)` and rejects extensions other than `.pcap` and `.pcapng` before parsing.
- `model.ts` mirrors the shared interfaces in this plan and is replaced by schema re-exports during integration.

- [ ] **Step 1: Scaffold the static SvelteKit test environment**

Use `@sveltejs/adapter-static`, Vitest browser-compatible jsdom tests, Testing Library, ESLint, and Prettier. Set `prerender = true` and `ssr = false` in `+layout.ts`. Install worktree dependencies with `pnpm --dir web install --lockfile=false`; do not commit a lane-local lockfile.

- [ ] **Step 2: Write failing component behavior tests**

```ts
it('shows the three-packet handshake overview', () => {
  render(CaptureOverview, { document: demoDocument });
  expect(screen.getByText('3 packets')).toBeInTheDocument();
  expect(screen.getByText('20 ms')).toBeInTheDocument();
});

it('labels all handshake events without using color alone', () => {
  render(TcpSequence, { flow: demoDocument.flows[0] });
  expect(screen.getByText('SYN')).toBeInTheDocument();
  expect(screen.getByText('SYN + ACK')).toBeInTheDocument();
  expect(screen.getByText('ACK')).toBeInTheDocument();
});
```

- [ ] **Step 3: Run tests and confirm components are missing**

Run: `pnpm --dir web test`

Expected: FAIL because the components do not exist.

- [ ] **Step 4: Implement the focused components**

Use semantic headings, buttons, tables, and lists. Include a skip link, visible focus styles, status text, table headers, and a text alternative for the sequence view. Do not use `{@html}`, canvas-only content, purple gradients, terminal styling, or arbitrary raw packet display.

- [ ] **Step 5: Add selection and keyboard tests**

Packet rows use real buttons. Selecting packet 1 shows Ethernet, IPv4, and TCP layer headings and the SYN explanation. The selected state uses text and `aria-current`, not color alone.

- [ ] **Step 6: Implement the page state with demo data**

The initial page shows the local-processing promise and file control. In test/demo state it can render `demoDocument`; integration will replace that path with worker results.

- [ ] **Step 7: Run frontend checks**

Run:

```bash
pnpm --dir web test
pnpm --dir web check
pnpm --dir web lint
pnpm --dir web build
```

Expected: all checks pass and the static build is under `web/build`.

- [ ] **Step 8: Commit**

```bash
git add web
git commit -m "feat: add the handshake inspection interface"
```

### Task 5: Integrate the Parallel Foundations

**Files:**

- Modify: root workspace and CMake files only when required for merged lanes.
- Modify: `web/src/lib/model.ts` to re-export schema types.
- Modify: affected test imports.

**Interfaces:**

- Root build sees core, CLI, schema, fixture, and web packages together.
- Web components import `CaptureDocument` from `@wirelens/schema` through `web/src/lib/model.ts`.

- [ ] **Step 1: Cherry-pick each reviewed lane commit into the Phase 1 branch**

Apply contract, C++, then frontend. Resolve only integration imports or root build references. Do not rewrite lane logic during the merge.

- [ ] **Step 2: Run the merged native and package tests**

Run:

```bash
cmake --preset native-debug
cmake --build --preset native-debug
ctest --preset native-debug --output-on-failure
pnpm install
pnpm --recursive test
pnpm --recursive --if-present check
```

Expected: all lane tests pass in one worktree. This first merged install creates the root `pnpm-lock.yaml`; all later installs use `--frozen-lockfile`.

- [ ] **Step 3: Parse the generated file with the native CLI**

Run:

```bash
build/native-debug/cli/wirelens fixtures/generated/tcp-handshake.pcap
build/native-debug/cli/wirelens fixtures/generated/tcp-handshake.pcap --json > build/native-debug/tcp-handshake.native.json
```

Expected summary: 3 packets, 20 ms duration, 1 TCP connection, complete handshake. The JSON validates with `schema/capture.schema.json`.

- [ ] **Step 4: Commit integration-only changes**

```bash
git add package.json pnpm-lock.yaml CMakeLists.txt web schema fixtures core cli
git commit -m "chore: integrate Phase 1 foundations"
```

### Task 6: WebAssembly Bridge

**Files:**

- Create: `wasm/CMakeLists.txt`
- Create: `wasm/include/wirelens/wasm_api.h`
- Create: `wasm/src/wasm_api.cpp`
- Create: `wasm/tests/wasm_api_test.cpp`
- Create: `scripts/build-wasm.sh`
- Create: `web/static/wasm/.gitkeep`

**Interfaces:**

```c
uintptr_t wirelens_alloc(size_t size);
uint32_t wirelens_parse_owned(uintptr_t data, size_t size);
int wirelens_result_ok(uint32_t handle);
const char* wirelens_result_data(uint32_t handle);
size_t wirelens_result_size(uint32_t handle);
const char* wirelens_result_error_code(uint32_t handle);
uint64_t wirelens_result_error_offset(uint32_t handle);
const uint8_t* wirelens_packet_data(uint32_t handle, size_t packet_index);
size_t wirelens_packet_size(uint32_t handle, size_t packet_index);
void wirelens_release(uint32_t handle);
```

`wirelens_parse_owned` takes ownership of a pointer returned by `wirelens_alloc`, including on failure. Handle `0` means allocation or registry failure. `wirelens_result_error_offset` returns `UINT64_MAX` when no offset exists.

- [ ] **Step 1: Write failing native ABI lifecycle tests**

Test successful parse, malformed parse, invalid handle, packet-byte retrieval, double release safety, and result registry cleanup. The test must confirm normalized JSON contains no raw bytes.

- [ ] **Step 2: Run and observe missing ABI failures**

Run: `ctest --preset native-debug -R WasmApi --output-on-failure`

Expected: FAIL because the ABI is missing.

- [ ] **Step 3: Implement the handle registry and ownership rules**

Use RAII objects and a mutex-protected registry. No exception crosses the C ABI. A result owns its original capture buffer, parsed document or error, and serialized text until release.

- [ ] **Step 4: Build the Emscripten module**

Use Emscripten 6.0.8 and these link settings:

```text
-sMODULARIZE=1
-sEXPORT_ES6=1
-sENVIRONMENT=worker,node
-sALLOW_MEMORY_GROWTH=1
-sFILESYSTEM=0
-sNO_EXIT_RUNTIME=1
```

Export only the declared C ABI and the runtime memory view needed to copy the selected `ArrayBuffer` once.

- [ ] **Step 5: Verify native and Emscripten builds**

Run:

```bash
cmake --build --preset native-debug --target wirelens_wasm_api_tests
ctest --preset native-debug -R WasmApi --output-on-failure
bash scripts/build-wasm.sh
```

Expected: native ABI tests pass and the build produces `web/static/wasm/wirelens.js` plus `web/static/wasm/wirelens.wasm`. These generated files remain ignored and are rebuilt before the web production build.

- [ ] **Step 6: Commit**

```bash
git add wasm scripts/build-wasm.sh web/static/wasm/.gitkeep
git commit -m "feat: expose the parser through WebAssembly"
```

### Task 7: Transferable Web Worker and Parser Client

**Files:**

- Create: `web/src/lib/worker/messages.ts`
- Create: `web/src/lib/worker/capture.worker.ts`
- Create: `web/src/lib/worker/parser-client.ts`
- Create: `web/src/lib/worker/parser-client.test.ts`
- Create: `web/src/lib/wasm/module.ts`

**Interfaces:**

```ts
export type WorkerRequest =
  | { type: 'parse'; requestId: string; fileName: string; buffer: ArrayBuffer }
  | { type: 'packet-bytes'; requestId: string; packetIndex: number }
  | { type: 'release'; requestId: string };

export type WorkerResponse =
  | { type: 'ready' }
  | { type: 'parse-complete'; requestId: string; document: CaptureDocument }
  | { type: 'packet-bytes'; requestId: string; packetIndex: number; buffer: ArrayBuffer }
  | { type: 'failed'; requestId: string; error: ParseError };
```

`ParserClient.parse(file)` checks the extension and 64 MiB size before `file.arrayBuffer()`. It posts the buffer with `[buffer]` as the transfer list. A new parse terminates the old worker and rejects its promise with `ParseCancelledError`.

- [ ] **Step 1: Write failing client lifecycle tests**

Use a small real fake Worker class that records messages and termination. Test transfer-list use, file-size rejection before worker creation, malformed response rejection, contract validation failure, replacement cancellation, and explicit disposal.

- [ ] **Step 2: Run and confirm the worker client is missing**

Run: `pnpm --dir web test -- parser-client.test.ts`

Expected: FAIL because `ParserClient` does not exist.

- [ ] **Step 3: Implement the parser client**

Use one pending request map keyed by request ID. Remove every request on resolve, reject, failure, termination, or disposal. Do not use random IDs; use a monotonic counter scoped to the client.

- [ ] **Step 4: Write failing worker integration tests**

Parse the generated fixture through the actual Emscripten module in the Vitest Node environment. Validate the returned document and request packet 1 bytes. Confirm release makes a later byte request fail.

- [ ] **Step 5: Implement the worker and module adapter**

The worker copies the transferred buffer into `wirelens_alloc` memory once, calls `wirelens_parse_owned`, parses UTF-8 JSON, validates it, and keeps one active handle. It releases the previous handle before accepting another capture and in the `release` command.

- [ ] **Step 6: Run worker gates**

Run:

```bash
pnpm --dir web test -- parser-client.test.ts
pnpm --dir web check
```

Expected: lifecycle and actual-module tests pass with no unhandled promise rejection.

- [ ] **Step 7: Commit**

```bash
git add web/src/lib/worker web/src/lib/wasm
git commit -m "feat: parse captures in a Web Worker"
```

### Task 8: Live UI Integration

**Files:**

- Modify: `web/src/routes/+page.svelte`
- Modify: `web/src/lib/components/CapturePicker.svelte`
- Modify: `web/src/lib/components/CaptureOverview.svelte`
- Modify: `web/src/lib/components/ConversationList.svelte`
- Modify: `web/src/lib/components/TcpSequence.svelte`
- Modify: `web/src/lib/components/PacketTable.svelte`
- Modify: `web/src/lib/components/PacketDetails.svelte`
- Create: `web/src/lib/capture-store.ts`
- Create: `web/src/lib/capture-store.test.ts`

**Interfaces:**

```ts
type CaptureState =
  | { status: 'empty' }
  | { status: 'loading'; fileName: string }
  | { status: 'ready'; fileName: string; document: CaptureDocument; selectedPacketId: string | null }
  | { status: 'error'; fileName: string | null; error: ParseError };
```

- [ ] **Step 1: Write failing store transition tests**

Cover empty to loading to ready, malformed input to error, a second file cancelling the first, packet selection, and disposal on page teardown.

- [ ] **Step 2: Run and observe failures**

Run: `pnpm --dir web test -- capture-store.test.ts`

Expected: FAIL because the store is missing.

- [ ] **Step 3: Implement the store and connect the page**

The page creates one `ParserClient` in the browser, disposes it on teardown, and never stores capture data in localStorage, sessionStorage, IndexedDB, cookies, or a service worker.

- [ ] **Step 4: Add page behavior tests**

Test local-processing copy, accessible file input, loading status, typed malformed error, three-packet overview, one TCP conversation, three sequence events, packet selection, and protocol-layer details.

- [ ] **Step 5: Implement remaining accessible states**

Loading uses `aria-busy`. Errors use `role="alert"`. Parse success moves focus to the capture heading. The sequence view retains its table alternative. The interface remains usable at 320, 768, 1024, and 1440 CSS pixels.

- [ ] **Step 6: Run UI gates**

Run:

```bash
pnpm --dir web test
pnpm --dir web check
pnpm --dir web lint
pnpm --dir web build
```

Expected: all pass with no console or accessibility warnings in tests.

- [ ] **Step 7: Commit**

```bash
git add web/src
git commit -m "feat: connect capture parsing to the interface"
```

### Task 9: Native and WebAssembly Contract Parity

**Files:**

- Create: `schema/src/golden.test.ts`
- Create: `web/src/lib/worker/wasm-parity.test.ts`
- Create: `scripts/check-contract-parity.mjs`
- Create: `fixtures/expected/tcp-handshake.capture.json`
- Modify: root package scripts.

**Interfaces:**

- `scripts/check-contract-parity.mjs <native-cli> <fixture> <wasm-module>` exits 0 only when parsed JSON values are deeply equal.
- The golden JSON is generated from a verified parser run, reviewed once, then checked for deterministic regeneration.

- [ ] **Step 1: Write a failing parity test that changes one nested value**

The test must prove the comparer rejects a changed TCP acknowledgment number, not only a top-level difference.

- [ ] **Step 2: Run and confirm the comparer is missing**

Run: `pnpm test:parity`

Expected: FAIL because the parity script does not exist.

- [ ] **Step 3: Implement semantic parity comparison**

Run the native CLI with `--json`. Load and run the Emscripten module against the same bytes. Validate each result, then compare parsed values. Do not compare whitespace or object-key source order.

- [ ] **Step 4: Create and validate the golden document**

The expected document must contain exactly three packets, one complete TCP flow, exact endpoints and sequence events, and no keys matching `raw`, `payload`, `authorization`, `cookie`, `token`, or `secret` case-insensitively.

- [ ] **Step 5: Run parity and schema gates**

Run:

```bash
pnpm test:parity
pnpm --dir schema test
```

Expected: native equals WebAssembly and both equal the reviewed golden document.

- [ ] **Step 6: Commit**

```bash
git add schema web/src/lib/worker scripts fixtures/expected package.json
git commit -m "test: prove native and WebAssembly contract parity"
```

### Task 10: Chromium Vertical-Slice Test and Screenshot

**Files:**

- Create: `web/playwright.config.ts`
- Create: `web/e2e/fixtures.ts`
- Create: `web/e2e/seed.spec.ts`
- Create: `web/e2e/specs/phase-1.plan.md`
- Create: `web/e2e/phase-1/inspect-tcp-handshake.spec.ts`
- Create: `artifacts/phase-1/.gitkeep`

**Interfaces:**

- Playwright starts the production preview server, uploads `fixtures/generated/tcp-handshake.pcap`, and saves a screenshot under `artifacts/phase-1/`.

- [ ] **Step 1: Write the user-level E2E test plan**

The scenario must select the handshake file, wait for the overview, open the only TCP conversation, confirm SYN/SYN+ACK/ACK, select packet 1, and confirm Ethernet/IPv4/TCP layers plus the SYN explanation.

- [ ] **Step 2: Write the failing Chromium test**

Use role and label locators. Do not use sleeps, `networkidle`, or fragile CSS selectors.

- [ ] **Step 3: Run and observe the first real failure**

Run: `PLAYWRIGHT_HTML_OPEN=never pnpm --dir web test:e2e --project=chromium`

Expected: FAIL until the production preview, WebAssembly asset path, and upload path work together.

- [ ] **Step 4: Diagnose and fix integration defects with the real browser**

Use Playwright CLI snapshots, console output, and request inspection. Every app defect found gets a focused failing unit or integration test before its fix.

- [ ] **Step 5: Capture proof**

After the test passes, save `artifacts/phase-1/handshake-overview.png` at 1440x1000 and a Playwright trace on failure only.

- [ ] **Step 6: Run Chromium twice only when code changed between runs**

Run: `PLAYWRIGHT_HTML_OPEN=never pnpm --dir web test:e2e --project=chromium`

Expected: PASS, zero page errors, and screenshot present.

- [ ] **Step 7: Commit**

```bash
git add web/playwright.config.ts web/e2e artifacts/phase-1
git commit -m "test: verify the browser handshake journey"
```

### Task 11: CI, Documentation, and Privacy Gates

**Files:**

- Create: `.github/workflows/ci.yml`
- Create: `.github/dependabot.yml`
- Create: `README.md`
- Create: `CONTRIBUTING.md`
- Create: `SECURITY.md`
- Create: `docs/reference/phase-1-contract.md`
- Create: `docs/reference/filter-and-protocol-roadmap.md`
- Modify: `scripts/check-secrets.sh`

**Interfaces:**

- CI runs native C++ build/tests, contract tests, Emscripten build, parity, frontend lint/typecheck/tests/build, Chromium Playwright, dependency audit, and privacy/secret scan.

- [ ] **Step 1: Add a local aggregate verification command**

`pnpm verify:phase1` must call native build/tests, WebAssembly build, all package tests, parity, frontend checks/build, secret scan, and Chromium E2E in fail-fast order.

- [ ] **Step 2: Run the aggregate command before CI exists**

Run: `pnpm verify:phase1`

Expected: FAIL because the aggregate command and CI support are incomplete.

- [ ] **Step 3: Implement CI with pinned major actions**

Use `actions/checkout@v4`, `actions/setup-node@v4`, and `actions/upload-artifact@v4`. Pin Node 22 and pnpm 11.24.0. Pin Emscripten 6.0.8. Upload Playwright reports only on failure. Do not use secrets or paid services.

- [ ] **Step 4: Document the exact Phase 1 capability**

README must state that Phase 1 supports classic PCAP Ethernet/IPv4/TCP handshake inspection and that later V1 protocol work is not yet complete. Document local-only parsing, file cap, CLI commands, browser commands, architecture, tests, and synthetic fixture license.

- [ ] **Step 5: Run privacy and dependency checks**

Run:

```bash
bash scripts/check-secrets.sh
pnpm audit --audit-level high
rg -n 'fetch\(|XMLHttpRequest|sendBeacon|WebSocket|EventSource|{@html}|innerHTML|localStorage|sessionStorage|indexedDB' web/src
```

Expected: no capture upload or unsafe rendering/storage path. Same-origin WebAssembly loading is the only expected browser fetch performed by generated module code outside `web/src`.

- [ ] **Step 6: Run the complete local verification command**

Run: `pnpm verify:phase1`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add .github README.md CONTRIBUTING.md SECURITY.md docs/reference scripts package.json
git commit -m "ci: gate the Phase 1 vertical slice"
```

### Task 12: Review, Pull Request, Green CI, and Merge

**Files:**

- Modify only files required by verified review or CI findings.

**Interfaces:**

- One Phase 1 pull request closes the Phase 1 implementation issue only when all acceptance criteria pass.

- [ ] **Step 1: Run the final local verification from a clean worktree**

Run:

```bash
git status --short
pnpm verify:phase1
git diff --check main...HEAD
```

Expected: clean worktree, all gates pass, no whitespace errors.

- [ ] **Step 2: Run a full branch review**

Review spec compliance, parser bounds, resource limits, memory ownership, contract precision, privacy, accessibility, test evidence, dependency scope, and CI correctness. One reproducible P0 or P1 blocks the PR.

- [ ] **Step 3: Fix supported findings test-first and rerun affected gates**

Each defect gets a failing test, minimal fix, affected suite, and then `pnpm verify:phase1`.

- [ ] **Step 4: Push the feature branch and open the pull request**

The PR body must link the Phase 1 issue and milestone, list exact checks, state that Phase 2 protocols remain out of scope, and include the screenshot path.

- [ ] **Step 5: Watch CI and resolve real failures**

Inspect failing job logs. Reproduce locally where possible. Do not rerun a flaky failure without finding its cause.

- [ ] **Step 6: Merge only after green CI and review**

Use a normal merge or squash according to the repository setting. Confirm `main` points at the merged result and the issue records proof.

- [ ] **Step 7: Record the Phase 1 checkpoint**

Report exact HEAD, repository state, test totals, native/WebAssembly parity, browser result, CI run, screenshot path, completed issue/PR, blockers, and Phase 2 priorities.
