import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const e2eDirectory = dirname(fileURLToPath(import.meta.url));

export const handshakeFixturePath = resolve(
  e2eDirectory,
  '../../fixtures/generated/tcp-handshake.pcap',
);

export const dnsFixturePath = resolve(e2eDirectory, '../../fixtures/generated/dns-exchanges.pcap');

export const httpFixturePath = resolve(
  e2eDirectory,
  '../../fixtures/generated/plaintext-http.pcap',
);

export const tlsFixturePath = resolve(e2eDirectory, '../../fixtures/generated/tls-handshake.pcap');

export const tcpResetFixturePath = resolve(e2eDirectory, '../../fixtures/generated/tcp-reset.pcap');

export const tcpRetransmissionFixturePath = resolve(
  e2eDirectory,
  '../../fixtures/generated/tcp-retransmission.pcap',
);
