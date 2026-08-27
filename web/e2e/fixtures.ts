import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const e2eDirectory = dirname(fileURLToPath(import.meta.url));

export const handshakeFixturePath = resolve(
  e2eDirectory,
  '../../fixtures/generated/tcp-handshake.pcap',
);
