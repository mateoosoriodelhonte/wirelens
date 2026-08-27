# WireLens V1 Design

Status: Proposed. James approved the architecture direction on 2026-08-27. The written specification still needs review.

Date: 2026-08-27

Project record:

- Local source of truth: `/Users/studio3/Code/Personal/wirelens`.
- Initial branch: `main`.
- Initial source state: empty Git tree `4b825dc642cb6eb9a060e54bf8d69288fbee4904`.
- GitHub owner: `mateoosoriodelhonte`.
- Planned public remote: `https://github.com/mateoosoriodelhonte/wirelens`.
- Existing remote, issue board, or pull request at design time: none.

## 1. Purpose

WireLens is a local-first visual network protocol inspector. It turns packet-capture bytes into packets, protocol layers, conversations, timing, and plain explanations.

WireLens V1 reads only files that a user selects. It does not capture, send, replay, intercept, scan, probe, or decrypt network traffic. It does not need a backend, an account, a paid service, root access, or administrator access.

The product serves learners and developers who need a clear account of what happened in a capture. It is not an intrusion-detection system. It reports neutral observations, not threats.

## 2. Approved Architecture Decision

WireLens will use one C++20 parser for the native CLI and browser application. Emscripten will compile the parser to WebAssembly. A normal JavaScript Web Worker will own the WebAssembly instance and parsing job.

The boundary between C++ and TypeScript will be a versioned, normalized JSON document. The Web Worker will hide the transport from the UI. This boundary lets a later release use a binary or streaming transport without changing UI domain concepts.

The browser data path is:

```text
Selected File
    |
    v
ArrayBuffer transferred to a Web Worker
    |
    v
One bounded copy into WebAssembly linear memory
    |
    v
C++ parser and analysis core
    |
    v
Versioned, sanitized normalized JSON
    |
    v
Worker contract validation
    |
    v
Svelte stores and views
```

The native data path is:

```text
Capture file -> C++ parser and analysis core -> text summary or the same normalized JSON
```

### 2.1 Why this option

The JSON boundary is easy to inspect, test, and export. It makes the C++ and TypeScript contract explicit. It also keeps the first release smaller than a binary schema or streaming parser would.

The main cost is peak memory. The worker holds the capture in WebAssembly memory while C++ builds the normalized model and serializes JSON. WireLens will measure this cost. It will not claim support for a capture size until native and browser measurements prove it.

### 2.2 Alternatives not selected for V1

**Binary contract:** A binary schema could reduce serialization cost. It would add schema tools, generated code, and debugging cost before measurements show that JSON is a problem.

**Incremental streaming:** Chunked parsing could support larger captures. It would make flow reconstruction, cancellation, ordering, and partial errors much harder. The V1 parser will use bounded whole-file input.

**Emscripten Wasm Workers or pthreads:** The parser does not need shared-memory parallelism in V1. A normal Web Worker keeps the page responsive and does not require cross-origin isolation headers.

## 3. Scope

### 3.1 Required capture formats

- Classic PCAP with little-endian and big-endian headers.
- Microsecond and nanosecond PCAP timestamps.
- Empty PCAP files with a valid global header.
- PCAPNG common Ethernet subset:
  - Section Header Block.
  - Interface Description Block.
  - Enhanced Packet Block.
  - `if_tsresol` when present, with the standard default when absent.

WireLens will reject a truncated or inconsistent block. It will report an unsupported required structure instead of guessing. It can skip an unknown block only when the block length is valid and the block is not needed to interpret a packet. The result will contain one warning and a count for each skipped block type. A new Section Header Block resets section byte order and interface definitions.

V1 supports Ethernet link type `DLT_EN10MB` only. A different link type is a clear unsupported-link error.

### 3.2 Required protocols

- Ethernet II, including an optional single or stacked 802.1Q VLAN tag when enough bytes are present.
- IPv4.
- IPv6 base headers and bounded traversal of Hop-by-Hop Options, Routing, Fragment, and Destination Options headers.
- TCP.
- UDP.
- DNS messages over UDP.
- Plaintext HTTP/1.x request and response headers over TCP.
- TLS record and handshake metadata needed to identify ClientHello, ServerHello, negotiated or offered versions, and SNI when visible.

WireLens will not reassemble IP fragments. It will show the IP layer and fragment facts. It will parse transport data only for an unfragmented datagram or the first fragment when the complete transport header is present. It will not pretend that a partial higher-layer message is complete.

V1 will do bounded, gap-aware TCP header reconstruction for HTTP and initial TLS handshakes. It will not reconstruct response bodies or offer a general TCP byte-stream export.

DNS decoding requires UDP source or destination port 53 and a structurally valid message. HTTP and TLS recognition can work on a nonstandard TCP port, but only after a strict request line, status line, TLS record header, or handshake header passes validation. Port number alone will not create an application-layer claim.

### 3.3 Required product views

- Capture entry with local file selection, drag and drop, and synthetic demos.
- Capture overview.
- Endpoint and protocol distribution.
- Conversation browser.
- TCP sequence view.
- DNS exchange view.
- Plaintext HTTP exchange view.
- Packet table and packet details.
- Protocol-layer tree.
- Optional hex view with field byte highlighting.
- Capture timeline.
- Filter and search.
- Learning mode.
- Observations.
- Sanitized Markdown and JSON export.

### 3.4 Non-goals

- Live capture or privileged interface access.
- Traffic generation, replay, scanning, or probing.
- TLS decryption.
- IP fragment reassembly.
- A complete PCAPNG implementation.
- A complete Wireshark display-filter language.
- General TCP stream or file extraction.
- Detection of attacks or malware.
- Multi-gigabyte capture support.
- Cloud storage, telemetry, or analytics.

## 4. Repository Layout

```text
wirelens/
  CMakeLists.txt
  CMakePresets.json
  core/
    include/wirelens/
    src/
    tests/
    fuzz/
  cli/
  wasm/
  schema/
  web/
  fixtures/
    generated/
    manifests/
  benchmarks/
  scripts/
  docs/
    decisions/
    reference/
    superpowers/specs/
  .github/workflows/
```

The core will not include browser or CLI code. The CLI and WebAssembly bridge will depend on the core. The web application will depend on the normalized contract, not C++ implementation types.

## 5. C++ Core

### 5.1 Bounded reader

All binary parsing will use a checked reader over `std::span<const std::byte>`. The reader will provide explicit little-endian and big-endian integer functions, bounded subspans, and checked offset movement.

Parser code will not use unchecked pointer arithmetic. A failed read will return a typed error. Exceptions will not cross the native CLI or WebAssembly boundary.

Each error will include, when known:

- Stable error code.
- Short user message.
- Capture byte offset.
- Packet index.
- Protocol or block context.

### 5.2 Capture parsing

The format detector will read magic bytes without assuming host byte order.

For classic PCAP, the parser will validate:

- Complete global header.
- Supported magic value and timestamp resolution.
- Supported version.
- Supported link type.
- Record header availability.
- `captured_length <= original_length`.
- Captured length against remaining input and configured limits.
- Timestamp conversion without integer overflow.

For PCAPNG, the parser will validate:

- Section byte-order magic.
- Minimum and aligned block length.
- Matching leading and trailing block lengths.
- Interface reference.
- Captured length against block data and configured limits.
- Per-interface link type and timestamp resolution.

### 5.3 Protocol decoding

Each decoder receives a bounded span and its absolute capture offset. It returns a protocol-layer value or a typed parse note. A malformed inner layer does not erase valid outer-layer facts.

Every exposed field can include a byte range:

```text
captureOffset: first byte in the capture
packetOffset: first byte relative to the captured frame
length: number of bytes
```

These ranges are the source of truth for hex highlighting.

DNS compression pointers will have cycle detection, an explicit hop limit, and name-length limits. TCP data offsets, IPv4 header lengths, IPv6 extension lengths, and TLS record lengths will be checked before access.

### 5.4 TCP connections

A TCP connection key contains both endpoint addresses, both ports, address family, and protocol. Direction is set by the first observed SYN without ACK. If the initial SYN is absent, direction is set by the first packet and the connection is marked as mid-stream.

A four-tuple can be reused. A new SYN without ACK after a reset or completed close starts a new connection instance. A new SYN with clearly different initial sequence state can also start a new instance after an inactive observed connection. When the evidence is ambiguous, WireLens keeps one mid-stream connection and records the limitation.

The state model records:

- Start and end timestamps.
- Packets, captured bytes, and original bytes.
- SYN, SYN-ACK, and completing ACK evidence.
- FIN evidence in each direction.
- RST evidence.
- Complete, partial, or unobserved handshake.
- Graceful, reset, open-at-capture-end, or unknown termination.

Sequence arithmetic will account for SYN and FIN consuming one sequence number. It will use serial-number comparisons so a 32-bit wrap does not become a false retransmission.

### 5.5 Retransmission heuristic

WireLens will use a conservative rule. A TCP segment is a retransmission candidate only when an earlier segment in the same connection and direction has the same sequence range and the same payload bytes. SYN or FIN state must also match.

The UI explanation will say that the segment appears to resend bytes already seen. It will not claim packet loss or a network fault. Ambiguous overlap, capture truncation, and sequence-wrap ambiguity will not produce this observation.

### 5.6 Bounded application parsing

For each TCP direction, the analyzer can retain a small ordered prefix for HTTP headers and initial TLS handshakes. A gap stops reconstruction for that message. Out-of-order data can fill a known gap only while all retained ranges stay inside the configured per-flow and global budgets.

HTTP parsing ends at the header terminator. WireLens does not retain request or response bodies. The parser pairs a request with the next valid response in the opposite direction when ordering is clear. Ambiguous exchanges remain unpaired.

TLS parsing reads only bounded record and handshake headers. It can inspect a visible ClientHello or ServerHello and safe extensions such as server name. It does not derive secrets, use key logs, or decrypt application data.

## 6. Normalized Contract

### 6.1 Authority and versioning

`schema/capture.schema.json` will be the transport-neutral source of truth. It will use JSON Schema 2020-12. Generated TypeScript types and contract fixtures will be checked into the repository.

Every result will include:

```json
{
  "schema": "wirelens.capture",
  "contractVersion": "1.0.0"
}
```

Compatibility rules are:

- Patch: clarification or validation fix with no data-shape change.
- Minor: additive optional fields that old clients can ignore.
- Major: removed fields, changed meaning, new closed-enum values, or another incompatible shape.

The UI will accept the major versions that it declares and ignore unknown optional object fields. An unknown major version or closed-enum value is a hard contract error. A binary or streaming transport can carry the same domain entities and contract version later.

### 6.2 Main entities

- `Capture`: format, timing, counts, link types, protocols, endpoints, limits, and warnings.
- `Packet`: number, timestamp, lengths, endpoints, summary, layers, flow reference, and analysis flags.
- `ProtocolLayer`: protocol, label, field values, byte ranges, and deterministic explanation keys.
- `Flow`: protocol, endpoints, timing, counts, TCP state, and ordered event references.
- `DnsExchange`: question, response, returned records, response code, and matched latency.
- `HttpExchange`: sanitized request and response lines, selected headers, and matched latency.
- `TlsHandshake`: visible record and handshake metadata, including SNI when present.
- `Observation`: stable type, neutral message, evidence packet references, and limitation text.
- `ParseDiagnostic`: severity, stable code, context, and byte offset.

Entity IDs will be deterministic within one parse. They will not contain random values or machine information.

### 6.3 Raw bytes

Raw packet bytes are not part of the normalized JSON. The worker keeps the WebAssembly result handle while a capture is open. The UI can request the bytes for one selected packet. The worker returns only that bounded byte range.

Closing a capture, choosing another capture, or terminating the worker releases the result handle and its input memory.

## 7. WebAssembly and Worker Boundary

Emscripten will produce a modularized ES module. The worker will create one module instance and will own all exported calls.

The bridge will use a small handle-based C ABI. It will provide operations to:

- Transfer ownership of an allocated input buffer to a parse operation.
- Obtain result status and normalized JSON bytes.
- Obtain a bounded packet byte range for the active result.
- Release the result and all owned memory.

The bridge will catch internal exceptions and convert them to typed failures. JavaScript will use `try/finally` so failed parsing and worker cancellation release memory.

The first worker message transfers the file `ArrayBuffer`. Transfer detaches the buffer from the main thread. The worker then copies it once into WebAssembly memory. Results use ordinary structured-clone messages because the normalized model is read by the main thread.

The worker protocol will use request IDs and these states:

- `ready`
- `parsing`
- `complete`
- `failed`
- `cancelled`

Selecting a new capture terminates the old worker before a replacement starts. This is the reliable cancellation path for V1.

## 8. Privacy and Export

The web application will make no capture-related network request. It will not include analytics, telemetry, remote fonts, or third-party runtime scripts. Demo captures and WebAssembly files will be same-origin static assets.

HTTP processing will use a small allowlist for displayed values. It can retain values for headers such as `Host`, `Content-Type`, `Content-Length`, `Accept`, `User-Agent`, `Server`, and `Date`. It will never retain values for:

- `Authorization`
- `Cookie`
- `Set-Cookie`
- `Proxy-Authorization`
- Header names that indicate tokens, API keys, sessions, secrets, credentials, or JWTs.

Unknown header values will not enter the normalized model. The model can state that a header was present and redacted. URL query values will be replaced with `[redacted]` by default. HTTP bodies will not enter the model.

Markdown and JSON exports will use only the sanitized normalized model. They will never contain raw packet bytes. Before download, the UI will warn that IP addresses, hostnames, and paths can still identify systems. An optional anonymized export will map endpoints and hostnames to stable labels within that report.

## 9. Filtering, Search, and Explanations

### 9.1 Filter grammar

The V1 grammar is deliberately small:

```text
filter  = term *(space term)
term    = "tcp" | "udp" | "dns" | "http" | "tls"
        | "ip:" ip-address
        | "port:" decimal-port
```

Terms are case-insensitive and combine with logical AND. There is no OR, NOT, parenthesis, range, or arbitrary field expression. An invalid token produces an inline error and does not change the current result set.

### 9.2 Search

Search uses a normalized lowercase index over packet number, IP address, hostname, port, protocol name, and sanitized HTTP path. The index contains no raw payload text.

### 9.3 Learning mode

Learning text is deterministic and keyed by protocol or field meaning. It is stored in the web source and reviewed like product copy. It does not use an AI service.

## 10. Observations

V1 can report:

- TCP reset.
- Incomplete observed handshake.
- Conservative retransmission candidate.
- DNS error response.
- Slow DNS response when enough comparison data exists.
- Connection without an observed close.

A slow DNS observation requires at least five matched DNS exchanges. Its latency must be at least 500 ms and at least three times the median latency of the other matched exchanges. If these conditions are not met, WireLens shows latency without calling it unusually slow.

Each observation will cite packet evidence and include a limitation where a capture can be incomplete.

## 11. User Interface

SvelteKit will use static output. Capture analysis will run only in the browser. Svelte stores will hold the normalized model, selection state, filters, and learning-mode state.

The main layout will have:

- A top bar with capture identity, privacy state, theme, and export.
- A compact left navigation for overview, conversations, timeline, and packets.
- A central evidence view.
- A contextual details panel for layers, field meaning, and hex selection.

D3 will be limited to protocol distribution, timeline, sequence diagrams, and latency plots. Ordinary controls, tables, navigation, and layout will use Svelte and CSS.

The visual language will use restrained light and dark themes, clear protocol labels, precise typography, and calm status colors. It will not imitate a terminal or an attack dashboard.

Every visualization will have a text or table alternative. Keyboard users can select conversations, packets, layers, and fields. Focus remains visible. Color is never the only signal. Animation respects reduced-motion settings. The target is WCAG 2.1 AA.

## 12. Limits and Resource Safety

The first vertical slice will use a conservative 64 MiB hard input cap. This is a safety cap, not a performance claim. Before V1 release, measured native and browser results will either confirm this cap or support a documented change.

Other limits will include:

- Maximum packet count.
- Maximum captured packet length.
- Maximum PCAPNG block length.
- Maximum protocol nesting and IPv6 extension count.
- Maximum DNS pointer hops, labels, and decoded name length.
- Maximum HTTP header bytes per message.
- Maximum retained application bytes per flow and per capture.
- Maximum diagnostic and observation counts.
- Maximum normalized JSON size.

Each limit will have a named constant, a test at the boundary, and a clear diagnostic. Limit failures are normal parse results, not crashes.

## 13. Synthetic Fixtures

WireLens will generate original deterministic captures. A bounded fixture builder will construct byte arrays and write test files. It will not open a network interface or send packets.

Required fixtures are:

- TCP three-way handshake.
- DNS query and successful response.
- Plaintext HTTP request and response.
- Exact TCP retransmission candidate.
- TCP reset.
- TLS ClientHello and ServerHello metadata.
- Big-endian and nanosecond PCAP.
- Common-subset PCAPNG.
- Truncated and malformed variants.

Each fixture will have a manifest with its intended packets, expected normalized facts, and license statement that identifies it as original synthetic data.

## 14. Testing and Verification

### 14.1 C++

- Unit tests for the bounded reader and endian helpers.
- Capture-format tests for all supported headers and failures.
- Protocol tests for valid, truncated, and inconsistent input.
- Flow-state and serial-number tests.
- Retransmission false-positive tests.
- Redaction tests.
- Deterministic serialization and contract fixture tests.
- AddressSanitizer and UndefinedBehaviorSanitizer builds.
- libFuzzer targets for capture detection, PCAP records, PCAPNG blocks, IPv4, IPv6, TCP, DNS, HTTP headers, and TLS handshakes.

### 14.2 TypeScript and Svelte

- Contract validation and unsupported-version tests.
- Worker success, malformed-input, cancellation, and memory-release tests.
- Store, filter, search, learning-mode, and export tests.
- Component tests for empty, loading, success, warning, and failure states.

### 14.3 Browser

Playwright will run the production static build. The main path will:

1. Load a synthetic capture.
2. Show the overview.
3. Open a TCP conversation.
4. Inspect the handshake sequence.
5. Open a packet and its layers.
6. Enable learning mode.
7. Filter DNS.
8. Export a sanitized report.

Chromium is required. Firefox is required unless a documented runner defect blocks it. Accessibility checks will cover names, focus, keyboard use, contrast, and text alternatives.

### 14.4 Contract integration

The native CLI and WebAssembly build will parse the same fixtures. Their normalized JSON will match after removal of explicitly allowed runtime metadata. TypeScript will validate every golden result against the checked-in schema.

## 15. Performance Measurement

Benchmarks will use only generated fixtures. Results will state the hardware, operating system, browser, build type, fixture size, packet count, and run count.

V1 will measure:

- Native parse throughput.
- WebAssembly parse throughput.
- Worker and module startup time.
- Time to first overview.
- Filter latency.
- Peak memory for representative captures.

The benchmark set will include small, medium, and limit-near captures built from deterministic packet patterns. Documentation will separate measured results from configured limits. A later binary or streaming transport needs evidence from these measurements and a new architecture decision record.

## 16. Toolchain and Dependencies

The initial audit found Apple Clang 21, Node 22.22.0, npm 10.9.2, and pnpm 11.24.0. CMake, Ninja, Emscripten, clang-format, and clang-tidy were not installed.

The project will pin its build and package versions. Emscripten 6.0.8 is the current stable release at the design date. Local setup will keep added tools inside the repository or a normal WireLens-specific cache. It will not change unrelated repositories or require a machine-wide installation.

Planned primary dependencies are:

- CMake for native and WebAssembly builds.
- Catch2 for C++ tests.
- `nlohmann/json` for deterministic JSON construction.
- SvelteKit with static adapter.
- TypeScript, Vite, and pnpm.
- D3 modules only for selected visualizations.
- Vitest and Playwright.
- JSON Schema generation and validation tools used at the contract boundary.

All dependencies must be free and have licenses compatible with a public open-source repository. Lockfiles or immutable version references will make builds reproducible.

## 17. CI, GitHub, and Release

The GitHub repository will be public under the authenticated personal account. Repository commits will use the account's personal no-reply address, not the current company address.

GitHub Actions will gate:

- CMake configure and native build.
- C++ tests and sanitizers.
- Formatting and practical static analysis.
- Emscripten build.
- Fixture contract comparison.
- Frontend install, lint, type check, unit tests, and production build.
- Playwright Chromium and Firefox paths.
- Dependency and security checks that need no paid service.

The `WireLens v1.0` milestone will track real implementation issues. Work will follow issue, branch, implementation, tests, pull request, green CI, and merge. Activity will reflect real work only.

GitHub Pages is the default deployment target. It needs no backend or extra account. A release is complete only after the deployed build passes the same synthetic vertical-slice path. The release tag will be `v1.0.0` and will point to the verified main commit.

## 18. Implementation Order

### Phase 1: End-to-end vertical slice

- Repository, toolchain, schema, and test foundations.
- Original synthetic TCP handshake PCAP.
- Safe classic-PCAP, Ethernet, IPv4, and TCP parsing.
- Native CLI summary and JSON.
- WebAssembly bridge.
- Transferable-buffer Web Worker.
- Svelte capture entry, overview, TCP conversation, sequence, and packet layers.
- Native, contract, frontend, and Playwright proof for this path.

This phase proves the architecture before broad protocol work starts.

### Phase 2: Capture and protocol breadth

- PCAP endian and timestamp variants.
- PCAPNG common subset.
- IPv6, UDP, DNS, HTTP redaction, and TLS metadata.
- Hex field ranges and selected-packet byte retrieval.

### Phase 3: Analysis

- TCP lifecycle and termination.
- Conservative retransmission candidates.
- DNS and HTTP exchange timing.
- Neutral observations.
- Versioned filtering and search behavior.

### Phase 4: Product completion

- Full overview and conversation browser.
- Timeline and latency views.
- Learning mode.
- Sanitized and anonymized exports.
- Accessibility and responsive layout.

### Phase 5: Hardening and release

- Adversarial tests, fuzzing, sanitizers, and static analysis.
- Performance and memory measurement.
- Documentation, architecture decisions, contribution guide, and security policy.
- Cross-browser verification.
- GitHub Pages deployment and live check.
- `v1.0.0` release.

## 19. Definition of Done

WireLens V1 is done only when a user can select a supported capture and inspect its overview, protocols, endpoints, conversations, packets, field ranges, TCP sequence, DNS, plaintext HTTP, TLS limitations, observations, filters, search, learning text, and sanitized exports without an upload or account.

The native CLI must parse the same fixtures and emit the same normalized contract. All required CI gates must pass. Performance claims and file-size guidance must come from recorded measurements. The public static deployment must pass the critical Playwright path against a synthetic capture.

Anything that does not meet these conditions remains open work. It will not be relabeled as complete for the release.

## 20. Technical References

- [Emscripten 6.0.8 release](https://github.com/emscripten-core/emscripten/releases/tag/6.0.8)
- [Emscripten modularized output](https://emscripten.org/docs/compiling/Modularized-Output.html)
- [Emscripten Wasm Workers guidance](https://emscripten.org/docs/api_reference/wasm_workers.html)
- [MDN transferable objects](https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Transferable_objects)
- [RFC 9293: Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc9293)
- [RFC 1035: Domain Names](https://www.rfc-editor.org/rfc/rfc1035)
- [RFC 8200: IPv6](https://www.rfc-editor.org/rfc/rfc8200)
- [RFC 9112: HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112)
- [RFC 8446: TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
