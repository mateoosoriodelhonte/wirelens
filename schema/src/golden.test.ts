import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { CaptureDocument, Packet } from './capture.js';
import { validateCaptureDocument } from './validate.js';

function readGolden(): CaptureDocument {
  const path = resolve(import.meta.dirname, '../../fixtures/expected/tcp-handshake.capture.json');
  return validateCaptureDocument(JSON.parse(readFileSync(path, 'utf8')));
}

function readFixtureGolden(name: string): CaptureDocument {
  const path = resolve(import.meta.dirname, `../../fixtures/expected/${name}.pcap.capture.json`);
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
    for (const name of [
      'tcp-handshake',
      'tcp-reset',
      'tcp-retransmission',
      'plaintext-http',
      'tls-handshake',
    ]) {
      expect(objectKeys(readFixtureGolden(name)).filter((key) => forbidden.test(key))).toEqual([]);
    }
  });

  it('validates sanitized HTTP exchange facts and excludes secret and body evidence', () => {
    const document = readFixtureGolden('plaintext-http');
    expect(document.httpExchanges).toEqual([
      expect.objectContaining({
        flowId: 'tcp-flow-1',
        matched: true,
        latencyNs: '20000000',
        request: expect.objectContaining({
          line: 'POST /search?term=[redacted]&sort=[redacted] HTTP/1.1',
          target: '/search?term=[redacted]&sort=[redacted]',
          packetNumbers: [4, 5],
          headers: expect.arrayContaining([
            { name: 'authorization', value: null, redacted: true },
            { name: 'cookie', value: null, redacted: true },
            { name: 'x-api-key', value: null, redacted: true },
          ]),
        }),
        response: expect.objectContaining({
          line: 'HTTP/1.1 200 OK',
          packetNumbers: [7],
        }),
      }),
    ]);
    expect(
      document.packets
        .filter((packet) => packet.layers.some((layer) => layer.protocol === 'HTTP'))
        .map((packet) => packet.number),
    ).toEqual([5, 7]);
    const serialized = JSON.stringify(document);
    expect(serialized).not.toContain('wirelens-http-header-secret-29');
    expect(serialized).not.toContain('wirelens-http-body-secret-29');
    expect(document.httpExchanges[0].request?.packetNumbers).not.toContain(6);
  });

  it('validates bounded matched TLS hello facts and packet evidence', () => {
    const document = readFixtureGolden('tls-handshake');
    expect(document.tlsHandshakes).toEqual([
      expect.objectContaining({
        flowId: 'tcp-flow-1',
        matched: true,
        limitation: 'WireLens does not decrypt TLS application data.',
        clientHello: expect.objectContaining({
          recordVersion: 'TLS 1.0',
          legacyVersion: 'TLS 1.2',
          offeredVersions: ['TLS 1.3', 'TLS 1.2'],
          serverName: 'example.test',
          packetNumbers: [4],
        }),
        serverHello: expect.objectContaining({
          recordVersion: 'TLS 1.2',
          legacyVersion: 'TLS 1.2',
          negotiatedVersion: 'TLS 1.3',
          packetNumbers: [5],
        }),
      }),
    ]);
    expect(
      document.packets
        .filter((packet) => packet.layers.some((layer) => layer.protocol === 'TLS'))
        .map((packet) => packet.number),
    ).toEqual([4, 5]);
  });

  it('validates reviewed TCP reset and retransmission evidence', () => {
    const reset = readFixtureGolden('tcp-reset');
    expect(reset.flows[0]).toMatchObject({
      handshake: 'complete',
      midStream: false,
      termination: 'reset',
    });
    expect(reset.observations).toEqual([
      expect.objectContaining({ type: 'tcp-reset', packetNumbers: [4] }),
    ]);

    const retransmission = readFixtureGolden('tcp-retransmission');
    expect(retransmission.flows[0]).toMatchObject({
      handshake: 'complete',
      midStream: false,
      termination: 'graceful',
    });
    expect(retransmission.observations).toEqual([
      expect.objectContaining({
        type: 'tcp-retransmission-candidate',
        packetNumbers: [4, 5],
      }),
    ]);
  });
});
