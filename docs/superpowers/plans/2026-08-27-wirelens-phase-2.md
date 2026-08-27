# WireLens Phase 2 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Use red-green-refactor. Workers must never spawn subagents.

**Goal:** Complete James's listed Phase 2 priorities: capture and protocol breadth, application metadata, analysis and observations, packet hex inspection, filters and search, and measured JSON-transport proof.

**Architecture:** Keep the approved C++20 parser and analysis core as the only parser. The CLI and Emscripten build serialize one versioned, sanitized normalized JSON document. A normal Web Worker owns the WASM instance, the capture input, the active result handle, and one bounded selected-packet byte response. Svelte consumes only validated domain data and the selected packet buffer. No capture data crosses a network boundary.

**Contract:** Use one coordinated `2.0.0` contract bump. The bump is required because `capture.format` changes from the closed value `pcap` to the closed values `pcap` and `pcapng`. Add the Phase 2 entities in this same major version. Do not change the transport. A binary or streaming transport requires benchmark evidence and a separate accepted architecture decision.

**Authority:** `docs/superpowers/specs/2026-08-27-wirelens-v1-design.md`

**Tracking:** Parent issue #30. Child issues #27, #28, #29, #26, #32, and #31.

## Global Constraints

- Use checked `std::span<const std::byte>` reads. No unchecked parser pointer arithmetic.
- Treat all capture lengths, offsets, counts, compression pointers, and nested protocol lengths as hostile.
- Keep the 64 MiB input cap and 65,536 packet cap unless recorded measurements justify a later change.
- Raw packet bytes stay outside normalized JSON, diagnostics, observations, search indexes, and exports.
- Keep one selected packet buffer at most in browser state.
- Do not add live capture, interface access, replay, scanning, probing, decryption, key logs, capture upload, analytics, telemetry, a backend, or a third-party runtime request.
- Fixtures must be original, deterministic, synthetic, and generated without network access.
- HTTP bodies and secret-bearing header values never enter any normalized field, layer, summary, diagnostic, golden, log, search index, or export.
- Claims stay neutral and cite packet evidence. Do not infer an attack, loss, or network fault.
- Each limit has a named constant, an exact boundary test, and a stable typed error or bounded diagnostic.
- Every child uses its own `codex/` branch and isolated worktree. Merge only after review, green local gates, and green GitHub CI.
- Use `Mateo Osorio Delhonte <259801526+mateoosoriodelhonte@users.noreply.github.com>` for repository commits.

## Dependency Order

1. Merge issue #27. It establishes contract `2.0.0`, capture detection, PCAPNG, IPv6, UDP, and core-owned packet source ranges.
2. Branch issues #28 and #26 from the new main. They may proceed in parallel only if their owned core/model paths do not overlap; otherwise merge #28 first.
3. Merge issue #29 after the shared flow and contract model is stable.
4. Merge issue #32 after all protocol entities and observations exist.
5. Merge issue #31 last. It owns the integrated verification gate, browser matrix, benchmarks, and final Phase 2 report.

## Stable Limits For This Plan

- `kMaxCaptureBytes = 64 MiB`.
- `kMaxPacketCount = 65,536`.
- `kMaxPcapngBlockBytes = 16 MiB`.
- `kMaxIpv6ExtensionHeaders = 8`.
- `kMaxDnsPointerHops = 16`.
- `kMaxDnsLabels = 127` and `kMaxDnsNameBytes = 255`.
- `kMaxDnsQuestions = 256` and `kMaxDnsRecords = 1,024` per message.
- `kMaxHttpHeaderBytes = 32 KiB` per message.
- `kMaxRetainedApplicationBytesPerDirection = 64 KiB`.
- `kMaxRetainedApplicationBytesPerCapture = 4 MiB`.
- `kMaxDiagnostics = 1,024` and `kMaxObservations = 1,024`.

If one value conflicts with a valid required fixture or causes a measurable regression, post the evidence on the child issue before changing it. Do not silently weaken a limit test.

## Task 1: Commit The Phase 2 Operating Plan

**Issue:** #30

**Files:**

- Create: `docs/superpowers/plans/2026-08-27-wirelens-phase-2.md`

- [ ] Verify the plan matches the accepted specification and all seven open Phase 2 issues.
- [ ] Run `pnpm exec prettier --check docs/superpowers/plans/2026-08-27-wirelens-phase-2.md`.
- [ ] Commit with `docs: plan WireLens Phase 2 #30`.
- [ ] Open a small PR that references #30 but does not close it. Merge after green CI.

## Task 2: Capture Formats, IPv6, UDP, And Contract V2

**Issue:** #27

**Primary files:**

- Modify: `core/include/wirelens/model.hpp`
- Modify: `core/include/wirelens/parser.hpp`
- Modify: `core/src/protocol_internal.hpp`
- Split/modify: `core/src/pcap_parser.cpp`
- Create: `core/src/pcapng_parser.cpp`
- Create: `core/src/ipv6_parser.cpp`
- Create: `core/src/udp_parser.cpp`
- Modify: `core/src/ethernet_parser.cpp`, `core/src/ipv4_parser.cpp`, `core/src/flow_builder.cpp`, `core/src/serialize.cpp`
- Modify: `core/CMakeLists.txt`, `core/tests/CMakeLists.txt`
- Add/modify: capture and protocol C++ tests plus fixture helpers
- Modify: `schema/capture.schema.json`, `schema/src/capture.ts`, validator tests, goldens
- Add/modify: deterministic fixture builders, manifests, generated captures, expected JSON
- Modify: `wasm/src/wasm_api.cpp`, ABI tests, worker error lists, parity scripts
- Modify: CLI tests and contract reference docs

### 2.1 Contract-first red tests

- [ ] Add failing schema tests for `contractVersion: "2.0.0"`, `capture.format: "pcapng"`, capture interfaces, packet `interfaceId`, general TCP/UDP flow union, and diagnostic counts.
- [ ] Keep explicit rejection tests for contract major `1` and unknown major `3` in the Phase 2 UI validator.
- [ ] Run `pnpm --dir schema test`; confirm RED for missing v2 shape.
- [ ] Implement the v2 TypeScript types and JSON Schema. Use unknown optional object-field tolerance, but keep closed enums strict.

### 2.2 Format-neutral packet source ranges

- [ ] Add failing C++ and WASM tests that retrieve exact packet bytes from both classic PCAP and PCAPNG.
- [ ] Add a private, non-serialized source range to the parsed result. Do not add it to `Packet` JSON.
- [ ] Remove the classic-PCAP scanner from `wasm/src/wasm_api.cpp`; read ranges from the successful core result.

### 2.3 Classic capture variants

- [ ] Add deterministic real-packet fixtures for big-endian microseconds and little-endian nanoseconds.
- [ ] Add RED tests for exact timestamp conversion, packet bytes, manifest hashes, goldens, and parity.
- [ ] Refactor capture detection so four available magic bytes select a format before format-specific minimum-length checks.

### 2.4 PCAPNG common subset

- [ ] Add RED tests for little/big-endian SHB, IDB, EPB, default and explicit decimal/binary `if_tsresol`, mixed interfaces, section reset, and safe unknown-block counts.
- [ ] Add RED tests for every malformed block condition in issue #27.
- [ ] Implement SHB/IDB/EPB with matching leading/trailing lengths, alignment, per-section interfaces, Ethernet link checks, packet padding exclusion, checked timestamps, and the 16 MiB block limit.
- [ ] Convert timestamp ticks to integer nanoseconds with checked integer arithmetic. Floor only sub-nanosecond remainder and document that representation rule; never round up.

### 2.5 IPv6 and UDP

- [ ] Add RED tests for IPv6 base/TCP, base/UDP, four supported extension types, no-next-header, unknown next header, fragments, truncation, payload bounds, address format, and extension limit.
- [ ] Add RED tests for UDP length 8, below 8, zero for IPv6 semantics, above bounded IP payload, and truncation.
- [ ] Implement bounded IPv6 extension traversal and UDP fields. Preserve valid outer layers when an inner layer is malformed.
- [ ] Generalize transport facts and endpoint families. Do not mislabel IPv6 endpoints as IPv4.

### 2.6 Fixture and parity proof

- [ ] Generate checked-in synthetic captures, manifests with SHA-256 and original-license text, and exact v2 goldens.
- [ ] Update the Phase 1 handshake golden to v2 without changing its observed facts.
- [ ] Run native CTest, sanitizer CTest, schema tests, CLI goldens, WASM tests, all fixture parity checks, formatting, privacy and secret scans.
- [ ] Open PR `Closes #27`, wait for green CI, review the exact merged head, and merge.

## Task 3: DNS Exchanges And DNS Observations

**Issue:** #28

**Primary files:**

- Create: `core/src/dns_parser.cpp`, `core/src/dns_builder.cpp`
- Modify: `core/include/wirelens/model.hpp`, `core/src/protocol_internal.hpp`, UDP integration, serializer
- Add: DNS parser/exchange/observation C++ tests
- Add: deterministic DNS fixture, manifest, golden, parity entries
- Modify: schema/types/validator tests
- Create: `web/src/lib/components/DnsExchangeList.svelte` and tests
- Modify: page/store/model wiring and Playwright fixtures/specs

- [ ] Write RED tests for valid query/response, A/AAAA answers, strict port 53 recognition, tuple-safe matching, unmatched/ambiguous cases, and exact latency.
- [ ] Write RED malformed-name tests for pointer self-cycle, two-node cycle, hop limit, label/name limits, section counts, and truncation.
- [ ] Implement DNS message facts using message-relative offsets and bounded recursion/iteration. Keep raw payload out of the document.
- [ ] Add `DnsExchange` and `Observation` v2 entities with deterministic IDs and packet evidence.
- [ ] Implement NXDOMAIN/SERVFAIL observations and slow-DNS boundaries: at least five matches, at least 500 ms, and at least three times the median of the other matches.
- [ ] Build the deterministic DNS fixture and exact native/WASM golden.
- [ ] Add accessible matched, unmatched, empty, response-code, latency, and evidence states in Svelte.
- [ ] Run targeted tests, full native/sanitizer tests, schema validation, parity, web tests/build, Chromium DNS path, privacy and secret scans.
- [ ] Open PR `Closes #28`, wait for green CI, review, and merge.

## Task 4: TCP Lifecycle, Retransmission, And Neutral Observations

**Issue:** #26

**Primary files:**

- Modify: `core/include/wirelens/model.hpp`
- Modify: `core/src/tcp_parser.cpp`, `core/src/flow_builder.cpp`, serializer
- Add: lifecycle, serial arithmetic, reuse, retransmission, and observation tests
- Add: retransmission and reset fixtures, manifests, goldens, parity
- Modify: schema/types and observation UI wiring as needed

- [ ] Write RED tests for SYN direction, mid-stream direction, full/partial/unobserved handshake, FIN/RST termination, open capture end, and four-tuple reuse.
- [ ] Write RED serial arithmetic tests for SYN/FIN consumption and 32-bit wrap.
- [ ] Write RED retransmission tests that require exact direction, sequence range, payload bytes, and SYN/FIN match, plus false-positive tests for overlap, truncation, gaps, and wrap ambiguity.
- [ ] Implement deterministic flow instances and the four approved TCP observation types with evidence and limitations.
- [ ] Enforce `kMaxObservations` and its exact boundary.
- [ ] Add deterministic reset and retransmission fixtures, goldens, schema checks, and native/WASM parity.
- [ ] Run full native/sanitizer, contract, parity, web component, privacy, and secret checks.
- [ ] Open PR `Closes #26`, wait for green CI, review, and merge.

## Task 5: Privacy-Safe HTTP And TLS Metadata

**Issue:** #29

**Primary files:**

- Create: `core/src/tcp_reassembly.cpp`, `core/src/http_parser.cpp`, `core/src/tls_parser.cpp`, application builders
- Modify: core model, TCP facts, serializer, schema/types
- Add: application limit, gap, redaction, TLS bounds, and pairing tests
- Add: HTTP and TLS fixtures, manifests, goldens, parity
- Create: HTTP/TLS Svelte views and tests
- Modify: page wiring and Playwright specs

- [ ] Write RED retained-prefix tests for ordered segments, a header terminator split across segments, in-budget gap fill, unresolved gaps, and per-direction/global limits.
- [ ] Write RED HTTP syntax, pairing, latency, allowlist, unknown-header, query-redaction, secret-header, and body-sentinel tests.
- [ ] Apply one sanitizer before any HTTP metadata enters a layer, exchange, summary, diagnostic, search field, golden, or export.
- [ ] Write RED TLS record, 24-bit handshake length, extension, SNI, version, malformed-random-port-443, and no-SNI tests.
- [ ] Implement only bounded HTTP headers and initial TLS ClientHello/ServerHello metadata. Do not retain bodies or key material.
- [ ] Add deterministic fixtures and exact native/WASM parity.
- [ ] Add accessible HTTP exchange/redaction and TLS metadata/no-decryption views.
- [ ] Prove unique secret and body sentinels are absent from all serialized and UI surfaces.
- [ ] Run full native/sanitizer, contract, parity, web/build/browser, privacy, and secret checks.
- [ ] Open PR `Closes #29`, wait for green CI, review, and merge.

## Task 6: Selected-Packet Hex, Filters, Search, And Evidence Navigation

**Issue:** #32

**Primary files:**

- Modify: worker/client/store selected-packet byte lifecycle
- Create: `web/src/lib/filter.ts`, `web/src/lib/search.ts` and tests
- Create: `web/src/lib/components/HexView.svelte`, `FilterSearch.svelte`, `ObservationList.svelte` and tests
- Modify: `PacketDetails.svelte`, `PacketTable.svelte`, page state/layout, styles
- Add: Playwright Phase 2 interaction spec and screenshots

- [ ] Write RED worker/client tests for exact packet buffer, invalid index, released handle, replacement, cancellation, stale response, and byte-fetch failure.
- [ ] Write RED range guards for `packetOffset + length <= buffer.byteLength`, including overflow-safe subtraction checks.
- [ ] Render a keyboard-selectable hex view. Highlight only the selected field range and keep at most one packet buffer.
- [ ] Write RED filter parser/evaluator tests for the exact grammar, case-insensitive AND, invalid-token preservation, and combined terms.
- [ ] Write RED search tests for only packet number, IP, hostname, port, protocol, and sanitized path. Prove a secret payload sentinel is not searchable.
- [ ] Add observation evidence navigation and accessible state/focus behavior.
- [ ] Move deterministic learning copy to a keyed web-source catalog for all displayed Phase 2 protocols.
- [ ] Run component/store/worker tests, typecheck, lint, format, production build, and Playwright Chromium exact-highlight/filter/search/evidence path.
- [ ] Open PR `Closes #32`, wait for green CI, review, and merge.

## Task 7: Benchmarks And Integrated Phase 2 Verification

**Issue:** #31

**Primary files:**

- Create: `benchmarks/` fixture generator, native runner, browser runner, result schema, and README
- Create: `scripts/verify-phase2.sh`
- Modify: root package scripts and `.github/workflows/ci.yml`
- Add: Phase 2 Playwright matrix/spec and artifact screenshots
- Modify: README, roadmap, contract reference, and Phase 2 evidence report

- [ ] Write RED determinism and result-shape tests for small, medium, and limit-near generated benchmark captures.
- [ ] Measure native throughput, WASM throughput, worker/module startup, first overview, filter latency, and peak memory. Use several warm runs and record run count without flaky pass/fail timing thresholds.
- [ ] Record hardware, OS, browser, build type, byte size, packet count, commands, raw samples, median, and peak memory.
- [ ] Record a transport decision note. Keep JSON unless results and a separately accepted ADR justify a change.
- [ ] Create one fail-fast `verify-phase2.sh` that runs all fixtures, native and sanitizer tests, WASM, every parity fixture, package tests, typecheck, lint, format, privacy, secret, dependency, static build, and required Chromium paths.
- [ ] Update CI to run the Phase 2 gate. Add Firefox only if it is runnable; otherwise record the exact runner defect and retain Chromium as required proof.
- [ ] Run the exact gate locally from a clean head. Record test totals and artifact hashes.
- [ ] Open PR `Closes #31`, wait for green CI, complete final code and privacy review, and merge.

## Task 8: Close The Phase 2 Parent

**Issue:** #30

- [ ] Verify every child issue is closed by its merged PR and every parent criterion is supported by current-main evidence.
- [ ] Run the exact Phase 2 gate on the final main commit.
- [ ] Verify clean/synced repository status, exact HEAD, CI run, parity, browser path, benchmark paths, screenshot hashes, and remaining V1 priorities.
- [ ] Post the evidence table to #30 and close it only after all checks pass.
- [ ] Do not deploy, tag, or release as part of Phase 2.
