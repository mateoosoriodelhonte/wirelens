# Phase 1 browser journey

1. Open the production static preview in Chromium.
2. Select `fixtures/generated/tcp-handshake.pcap` with the labeled capture file input.
3. Wait for the capture overview and verify three packets and one complete TCP conversation.
4. Open the only conversation and verify the SYN, SYN + ACK, and ACK sequence.
5. Select packet 1 and verify the Ethernet, IPv4, and TCP layers.
6. Verify the learning-mode explanation for the SYN flag.
7. Verify that the page has no console or page errors and makes no external HTTP(S) request.
8. Save a 1440 x 1000 screenshot to `artifacts/phase-1/handshake-overview.png`.
