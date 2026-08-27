import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { CaptureDocument, Packet } from './capture.js';
import { validateCaptureDocument } from './validate.js';

function readGolden(): CaptureDocument {
  const path = resolve(import.meta.dirname, '../../fixtures/expected/tcp-handshake.capture.json');
  return validateCaptureDocument(JSON.parse(readFileSync(path, 'utf8')));
}

function fieldValue(packet: Packet, name: string): string {
  for (const layer of packet.layers) {
    const field = layer.fields.find((candidate) => candidate.name === name);
    if (field) return field.value;
  }
  throw new Error(`Missing ${name} in packet ${packet.number}`);
}

function objectKeys(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(objectKeys);
  if (!value || typeof value !== 'object') return [];
  return Object.entries(value).flatMap(([key, child]) => [key, ...objectKeys(child)]);
}

describe('reviewed handshake golden document', () => {
  it('matches the versioned three-packet TCP contract', () => {
    const document = readGolden();
    expect(document.schema).toBe('wirelens.capture');
    expect(document.contractVersion).toBe('2.0.0');
    expect(document.packets).toHaveLength(3);
    expect(document.packets.map((packet) => packet.layers.map((layer) => layer.protocol))).toEqual([
      ['ETHERNET', 'IPV4', 'TCP'],
      ['ETHERNET', 'IPV4', 'TCP'],
      ['ETHERNET', 'IPV4', 'TCP'],
    ]);
    expect(document.packets.map((packet) => packet.layers.map((layer) => layer.label))).toEqual([
      ['Ethernet II', 'IPv4', 'TCP'],
      ['Ethernet II', 'IPv4', 'TCP'],
      ['Ethernet II', 'IPv4', 'TCP'],
    ]);
    expect(document.endpoints).toEqual([
      { id: 'endpoint-1', address: '192.0.2.10', port: 51515, addressFamily: 'ipv4' },
      { id: 'endpoint-2', address: '198.51.100.20', port: 443, addressFamily: 'ipv4' },
    ]);

    expect(document.flows).toHaveLength(1);
    expect(document.flows[0]).toMatchObject({
      id: 'tcp-flow-1',
      protocol: 'TCP',
      clientEndpointId: 'endpoint-1',
      serverEndpointId: 'endpoint-2',
      handshake: 'complete',
      packetNumbers: [1, 2, 3],
      events: [
        { packetNumber: 1, label: 'SYN' },
        { packetNumber: 2, label: 'SYN + ACK' },
        { packetNumber: 3, label: 'ACK' },
      ],
    });
    expect(document.packets.map((packet) => fieldValue(packet, 'sequenceNumber'))).toEqual([
      '1000',
      '5000',
      '1001',
    ]);
    expect(document.packets.map((packet) => fieldValue(packet, 'acknowledgmentNumber'))).toEqual([
      '0',
      '1001',
      '5001',
    ]);
  });

  it('contains no sensitive or raw payload object keys', () => {
    const forbidden = /raw|payload|authorization|cookie|token|secret/i;
    expect(objectKeys(readGolden()).filter((key) => forbidden.test(key))).toEqual([]);
  });
});
