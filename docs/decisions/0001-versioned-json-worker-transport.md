# Decision 0001: Keep the versioned JSON worker transport

- Status: accepted
- Date: 2026-08-27
- Authority: approved WireLens V1 design and Phase 2 issue #31

## Decision

WireLens keeps the versioned normalized JSON contract for native and browser
results. A normal Web Worker owns the WebAssembly module, the capture buffer,
and the active result handle. The main browser thread receives the validated
normalized document. Packet bytes are outside JSON and cross the worker
boundary only for one selected packet in a transferable buffer.

The transport contract stays at `2.0.0` for Phase 2. Benchmark code measures
native parse and serialization, WebAssembly work, JSON decode and parse,
structured-clone worker transport, and time to the first visible overview.

## Review triggers

A binary or streaming design can be studied only when reproducible results on
the medium profile show one of these conditions:

- JSON decode, parse, and warm worker transport together use more than
  25% of median time to the first visible overview;
- the same work has a median cost above 100 ms;
- the browser cannot complete the profile inside the documented limits because
  of transport memory, not parser or UI work.

A trigger starts a separate architecture review. It does not approve a
transport change. Any replacement must keep native/browser parity, privacy
rules, bounded ownership, typed errors, and compatibility tests. It also needs
a migration plan and a separately accepted decision.

## Result

The measured Phase 2 result and raw samples are recorded in the Phase 2
evidence artifact. Configured safety limits remain separate from measured
guidance. No Phase 2 benchmark can weaken a safety limit or add capture upload,
telemetry, a backend, or a network request.
