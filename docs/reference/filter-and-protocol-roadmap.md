# Protocol and inspection status

WireLens Phase 2 keeps one bounded C++ parser for native and browser use.

| Area          | Phase 2 status                                                          | Boundary                          |
| ------------- | ----------------------------------------------------------------------- | --------------------------------- |
| Classic PCAP  | Little- and big-endian, microsecond and nanosecond variants             | Offline files only                |
| PCAPNG        | Common section, interface, and enhanced-packet blocks                   | Bounded blocks and interfaces     |
| Ethernet      | Ethernet II with bounded VLAN tags                                      | No other link types               |
| IPv4 and IPv6 | IPv4 plus bounded IPv6 extension traversal                              | No fragment reassembly            |
| TCP and UDP   | Flow facts, TCP lifecycle, reset, and retransmission evidence           | No stream export                  |
| DNS           | Bounded questions, answers, exchange matching, and neutral observations | Port 53 only                      |
| HTTP          | Sanitized HTTP/1.0 and HTTP/1.1 request/response metadata               | No bodies; secret values redacted |
| TLS           | Initial ClientHello and ServerHello metadata                            | No decryption or key material     |
| Inspection    | Packet table, layers, sequence, selected-packet hex, field highlight    | One packet buffer at most         |
| Filter        | Case-insensitive AND terms for protocol, IP, and port                   | Invalid text stays visible        |
| Search        | Packet number, IP, hostname, port, protocol, and sanitized path         | No raw payload index              |
| Evidence      | Neutral observations link to packet evidence                            | No attack or fault claims         |

Later V1 work can add more bounded protocol detail, usability work, and
measured performance changes. A binary or streaming transport needs benchmark
evidence and a separate accepted architecture decision.

The product does not add live capture, interface access, packet sending,
replay, scanning, probing, decryption, capture upload, a backend, telemetry, or
analytics.
