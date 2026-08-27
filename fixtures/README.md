# WireLens synthetic fixtures

These files are original, deterministic synthetic traffic. They contain no
packets captured from a network interface and the builder never opens an
interface or sends a packet.

Build the handshake fixture with:

```sh
pnpm --dir fixtures build
```

`generated/tcp-handshake.pcap` is a 234-byte classic little-endian PCAP. It
contains three 54-byte Ethernet/IPv4/TCP frames: SYN, SYN + ACK, and ACK.
The expected checksum and packet facts are in
`manifests/tcp-handshake.json`.
