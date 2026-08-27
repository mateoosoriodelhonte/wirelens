# Phase 1 contract reference

The file `schema/capture.schema.json` is the source of truth for the
transport-neutral result. Every valid result has these exact root values:

```json
{
  "schema": "wirelens.capture",
  "contractVersion": "1.0.0"
}
```

The top-level document contains `capture`, `endpoints`, `packets`, `flows`, and
`diagnostics`. Phase 1 uses classic PCAP timing and reports a 64 MiB input cap.
Packet and flow IDs are deterministic: `packet-<one-based-number>` and
`tcp-flow-<one-based-number>`. Protocol names are uppercase, such as
`ETHERNET`, `IPV4`, and `TCP`.

Absolute and relative nanosecond times are decimal strings. A valid decimal
time is `0` or a non-zero digit followed by digits. This avoids loss of integer
precision in JavaScript. Byte counts and offsets are non-negative integers.

Every byte range has `captureOffset`, `packetOffset`, and `length`. These ranges
let the UI highlight fields without putting packet bytes in JSON. Raw packet
bytes are not part of the Phase 1 contract.

Unknown optional object fields are allowed for minor-version compatibility.
Unknown major versions and unknown values in closed enums are errors. A patch
version clarifies or fixes validation without changing shape. A minor version
adds optional data. A major version removes or changes data meaning.

The TypeScript validator parses JSON values and checks the schema before a
document enters UI state. Native and WebAssembly output must be semantically
equal for the same fixture; key order and JSON formatting are not part of the
contract.

## Parse errors

The native and WebAssembly boundaries return typed errors for oversized input,
truncated headers or data, unsupported magic or version, unsupported link type,
and invalid packet lengths. An error may include a capture offset and packet
number. No exception crosses these boundaries.

## Phase 1 proof boundary

The checked-in proof uses one deterministic three-frame Ethernet/IPv4/TCP
handshake. PCAPNG, IPv6, UDP/DNS, HTTP, TLS, filtering, and export work remain
roadmap items for later V1 work even though the versioned contract has room for
those entities.
