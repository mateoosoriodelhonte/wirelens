import { describe, expect, it } from 'vitest';
import type { DnsExchange, HttpExchange, TlsHandshake } from './model';
import { demoDocument } from './demo-document';
import { buildSearchIndex, searchPackets, searchDocument } from './search';

const document = {
  ...demoDocument,
  packets: [
    ...demoDocument.packets,
    {
      ...demoDocument.packets[0],
      id: 'packet-7',
      number: 7,
      layers: [
        ...demoDocument.packets[0].layers,
        {
          protocol: 'DNS' as const,
          label: 'DNS query',
          fields: [],
          byteRange: null,
          explanationKey: null,
        },
      ],
    },
    {
      ...demoDocument.packets[0],
      id: 'packet-8',
      number: 8,
      layers: [
        ...demoDocument.packets[0].layers,
        {
          protocol: 'DNS' as const,
          label: 'DNS response',
          fields: [],
          byteRange: null,
          explanationKey: null,
        },
      ],
    },
    {
      ...demoDocument.packets[0],
      id: 'packet-9',
      number: 9,
      layers: [
        ...demoDocument.packets[0].layers,
        {
          protocol: 'HTTP' as const,
          label: 'HTTP request',
          fields: [],
          byteRange: null,
          explanationKey: null,
        },
      ],
    },
    {
      ...demoDocument.packets[0],
      id: 'packet-10',
      number: 10,
      layers: [
        ...demoDocument.packets[0].layers,
        {
          protocol: 'TLS' as const,
          label: 'TLS ClientHello',
          fields: [],
          byteRange: null,
          explanationKey: null,
        },
      ],
    },
  ],
  dnsExchanges: [
    {
      id: 'dns-1',
      question: { name: 'Alpha.Example.test.', type: 1, class: 1 },
      queryPacketNumber: 7,
      responsePacketNumber: 8,
      responseCode: 'NOERROR',
      answers: [
        { name: 'alpha.example.test.', type: 1, class: 1, value: '203.0.113.44' },
        { name: 'alpha.example.test.', type: 99, class: 1, value: 'BODY_SECRET_SENTINEL' },
      ],
      latencyNs: '1000',
      matched: true,
    } satisfies DnsExchange,
  ],
  httpExchanges: [
    {
      id: 'http-1',
      flowId: 'tcp-flow-1',
      request: {
        line: 'GET /private?token=BODY_SECRET_SENTINEL HTTP/1.1',
        method: 'GET',
        target: '/private?token=BODY_SECRET_SENTINEL',
        version: 'HTTP/1.1',
        headers: [
          { name: 'Host', value: 'Web.Example.test', redacted: false },
          { name: 'Authorization', value: 'Bearer BODY_SECRET_SENTINEL', redacted: false },
        ],
        packetNumbers: [9],
        body: 'BODY_SECRET_SENTINEL',
      },
      response: null,
      latencyNs: null,
      matched: false,
    } satisfies HttpExchange,
  ],
  tlsHandshakes: [
    {
      id: 'tls-1',
      flowId: 'tcp-flow-1',
      clientHello: {
        recordVersion: 'TLS 1.2',
        legacyVersion: 'TLS 1.2',
        offeredVersions: ['TLS 1.3'],
        serverName: 'TLS.Example.test.',
        packetNumbers: [10],
      },
      serverHello: null,
      matched: false,
      limitation: '',
    } satisfies TlsHandshake,
  ],
  diagnostics: [
    {
      severity: 'warning' as const,
      code: 'secret',
      message: 'BODY_SECRET_SENTINEL',
      context: 'payload',
      captureOffset: null,
      packetNumber: 9,
      count: null,
    },
  ],
};

describe('privacy-safe packet search', () => {
  it('searches only normalized packet number, IP, port, protocol, and evidence metadata', () => {
    const index = buildSearchIndex(document);
    expect(searchPackets(index, '203.0.113.44')).toEqual([{ packetNumber: 8 }]);
    expect(searchPackets(index, 'alpha.example.test')).toEqual([
      { packetNumber: 7 },
      { packetNumber: 8 },
    ]);
    expect(searchPackets(index, 'http web.example.test private')).toEqual([{ packetNumber: 9 }]);
    expect(searchPackets(index, 'tls tls.example.test')).toEqual([{ packetNumber: 10 }]);
    expect(searchPackets(index, '51515')).toEqual([
      { packetNumber: 1 },
      { packetNumber: 2 },
      { packetNumber: 3 },
      { packetNumber: 7 },
      { packetNumber: 8 },
      { packetNumber: 9 },
      { packetNumber: 10 },
    ]);
  });

  it('is case-insensitive, uses AND terms, and has clear empty-query behavior', () => {
    expect(searchDocument(document, 'ALPHA EXAMPLE')).toEqual([
      { packetNumber: 7 },
      { packetNumber: 8 },
    ]);
    expect(searchDocument(document, 'alpha missing')).toEqual([]);
    expect(searchDocument(document, '   ')).toEqual([]);
  });

  it('does not index raw payload, unsafe headers, diagnostics, unknown DNS values, or arbitrary JSON', () => {
    const sentinel = 'BODY_SECRET_SENTINEL';
    expect(searchDocument(document, sentinel)).toEqual([]);
    expect(JSON.stringify(buildSearchIndex(document))).not.toContain(sentinel);
  });
});
