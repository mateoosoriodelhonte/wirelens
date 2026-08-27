# Filter and protocol roadmap

This page separates the Phase 1 proof from the wider V1 design. A listed item
is not a claim that the current UI implements it.

| Area           | Phase 1 status                                      | Later V1 direction                                                                 |
| -------------- | --------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Classic PCAP   | Proven with a deterministic little-endian fixture   | Add more valid and invalid capture cases                                           |
| Ethernet       | Proven, including bounded 802.1Q/802.1ad tag decode | Broader stacked-tag cases and field-detail tests                                   |
| IPv4           | Proven                                              | Fragment facts without fragment reassembly                                         |
| TCP            | Proven for a three-packet SYN/SYN-ACK/ACK flow      | Bounded flows, sequence events, retransmission evidence, HTTP and TLS metadata     |
| PCAPNG         | Not in the Phase 1 proof                            | Validate common Section Header, Interface Description, and Enhanced Packet blocks  |
| IPv6           | Not in the Phase 1 proof                            | Base and bounded extension-header traversal                                        |
| UDP and DNS    | Not in the Phase 1 proof                            | Structurally valid DNS exchanges and latency                                       |
| HTTP           | Not in the Phase 1 proof                            | Sanitized request/response headers and pairing                                     |
| TLS            | Not in the Phase 1 proof                            | Visible ClientHello/ServerHello metadata and SNI                                   |
| Filter grammar | Not exposed in the Phase 1 UI                       | Case-insensitive AND terms: `tcp`, `udp`, `dns`, `http`, `tls`, `ip:`, and `port:` |
| Search         | Not exposed in the Phase 1 UI                       | Normalized index without raw payload text                                          |

The roadmap does not add live capture, packet sending, replay, scanning,
probing, decryption, raw stream export, telemetry, or capture upload. Those are
outside the approved product boundary.
