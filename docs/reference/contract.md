# Normalized capture contract

`schema/capture.schema.json` is the source of truth for the transport-neutral
result. The Phase 2 document has these root values:

```json
{
  "schema": "wirelens.capture",
  "contractVersion": "2.0.0"
}
```

The root contains capture facts, endpoints, packets, TCP and UDP flows, DNS
exchanges, sanitized HTTP exchanges, TLS handshake metadata, neutral
observations, and bounded diagnostics. Capture format is `pcap` or `pcapng`.
The same document is produced by the native CLI and the WebAssembly build.

Absolute and relative nanosecond times are decimal strings. This avoids loss
of integer precision in JavaScript. Byte counts and offsets are non-negative
integers. Packet IDs and related evidence numbers are deterministic.

Each protocol layer or field can have a byte range with `captureOffset`,
`packetOffset`, and `length`. The range identifies bytes in the owned capture.
Raw packet bytes are not serialized. The browser requests bytes only for the
selected packet, and keeps at most one selected-packet buffer.

Unknown optional object fields are allowed for minor-version compatibility.
Closed enums stay strict. Consumers reject unknown major versions. A patch
version clarifies or fixes validation without a shape change. A minor version
adds optional data. A major version removes data or changes its meaning.

## Privacy rules

The normalized document does not contain raw packet payloads. HTTP metadata is
limited to an allowlist. Query values and secret-bearing header values are
redacted before they can reach a layer, summary, diagnostic, search index,
golden file, or export. HTTP bodies and TLS key material are not retained.
Hostnames, IP addresses, ports, and sanitized paths can still identify a
system. Treat a normalized document as private data.

## Parse errors and limits

Native and WebAssembly boundaries return typed errors. No exception crosses a
public boundary. Checked readers enforce these main limits:

- capture size: 64 MiB;
- packet count: 65,536;
- PCAPNG block size: 16 MiB;
- IPv6 extension headers: 8;
- diagnostics and observations: 1,024 each;
- retained application prefix: 64 KiB per direction and 4 MiB per capture.

These are safety limits. They are not performance claims. More protocol limits
are named in `core/include/wirelens/parser.hpp` and have boundary tests.

## Compatibility proof

Every checked-in synthetic capture has a deterministic manifest and golden
document. The parity gate compares the native result, WebAssembly result, and
golden document for every fixture. Formatting and JSON key order are not part
of the contract.
