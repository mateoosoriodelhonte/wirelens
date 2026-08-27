import { describe, expect, it } from 'vitest';
import { validateCaptureDocument } from './validate.js';

describe('validateCaptureDocument', () => {
  const minimal = () => ({
    schema: 'wirelens.capture',
    contractVersion: '2.0.0',
    capture: {
      format: 'pcap',
      timestampResolution: 'microseconds',
      packetCount: 0,
      capturedBytes: 0,
      originalBytes: 0,
      startTimestampNs: null,
      endTimestampNs: null,
      durationNs: '0',
      interfaces: [],
    },
    endpoints: [],
    packets: [],
    flows: [],
    dnsExchanges: [],
    observations: [],
    diagnostics: [],
  });

  it('rejects an unknown contract major version', () => {
    expect(() =>
      validateCaptureDocument({ schema: 'wirelens.capture', contractVersion: '1.0.0' }),
    ).toThrow(/contractVersion/);
  });

  it('rejects both the previous major and an unknown future major', () => {
    expect(() =>
      validateCaptureDocument({ schema: 'wirelens.capture', contractVersion: '1.0.0' }),
    ).toThrow(/contractVersion/);
    expect(() =>
      validateCaptureDocument({ schema: 'wirelens.capture', contractVersion: '3.0.0' }),
    ).toThrow(/contractVersion/);
  });

  it('accepts the minimal Phase 1 document', () => {
    const value = minimal();
    expect(validateCaptureDocument(value)).toEqual(value);
  });

  it('accepts a PCAPNG interface and a UDP flow in contract v2', () => {
    const value = minimal() as Record<string, any>;
    value.capture.format = 'pcapng';
    value.capture.interfaces = [
      { id: 0, linkType: 1, snapLength: 0, timestampResolution: 'nanoseconds' },
    ];
    value.flows = [
      {
        id: 'udp-flow-1',
        protocol: 'UDP',
        clientEndpointId: 'endpoint-1',
        serverEndpointId: 'endpoint-2',
        startTimestampNs: '0',
        endTimestampNs: '1',
        packetNumbers: [1],
        capturedBytes: 8,
        originalBytes: 8,
      },
    ];
    expect(validateCaptureDocument(value)).toEqual(value);
  });

  it('accepts DNS exchanges and bounded neutral observations', () => {
    const value = minimal() as Record<string, any>;
    value.dnsExchanges = [
      {
        id: 'dns-exchange-1',
        question: { name: 'example.com', type: 1, class: 1 },
        queryPacketNumber: 1,
        responsePacketNumber: 2,
        responseCode: 'NOERROR',
        answers: [{ name: 'example.com', type: 1, class: 1, value: '192.0.2.53' }],
        latencyNs: '500000000',
        matched: true,
      },
    ];
    value.observations = [
      {
        id: 'observation-1',
        type: 'slow-dns',
        message: 'DNS response latency met the slow-response rule',
        packetNumbers: [1, 2],
        limitation: 'Only packets in this capture were considered.',
      },
    ];
    expect(validateCaptureDocument(value)).toEqual(value);
  });

  it('accepts the observation boundary and rejects the next item', () => {
    const value = minimal() as Record<string, any>;
    value.observations = Array.from({ length: 1024 }, (_, index) => ({
      id: `observation-${index + 1}`,
      type: 'dns-error',
      message: 'DNS response returned NXDOMAIN',
      packetNumbers: [1],
      limitation: 'Only packets in this capture were considered.',
    }));
    expect(validateCaptureDocument(value)).toEqual(value);
    value.observations.push({ ...value.observations[0], id: 'observation-1025' });
    expect(() => validateCaptureDocument(value)).toThrow(/1024/);
  });

  it('accepts the DNS root name representation', () => {
    const value = minimal() as Record<string, any>;
    value.dnsExchanges = [
      {
        id: 'dns-exchange-1',
        question: { name: '.', type: 1, class: 1 },
        queryPacketNumber: 1,
        responsePacketNumber: null,
        responseCode: null,
        answers: [],
        latencyNs: null,
        matched: false,
      },
    ];
    expect(validateCaptureDocument(value)).toEqual(value);
  });

  it('accepts the DNS answer boundary and rejects the next item', () => {
    const value = minimal() as Record<string, any>;
    const answer = { name: 'example.com', type: 1, class: 1, value: '192.0.2.53' };
    value.dnsExchanges = [
      {
        id: 'dns-exchange-1',
        question: { name: 'example.com', type: 1, class: 1 },
        queryPacketNumber: 1,
        responsePacketNumber: 2,
        responseCode: 'NOERROR',
        answers: Array.from({ length: 1024 }, () => ({ ...answer })),
        latencyNs: '1',
        matched: true,
      },
    ];
    expect(validateCaptureDocument(value)).toEqual(value);
    value.dnsExchanges[0].answers.push({ ...answer });
    expect(() => validateCaptureDocument(value)).toThrow(/1024/);
  });

  it('requires diagnostic count and accepts a positive aggregate count', () => {
    const value = minimal() as Record<string, any>;
    value.diagnostics = [
      {
        severity: 'warning',
        code: 'UNKNOWN_PCAPNG_BLOCK',
        message: 'unknown',
        context: 'pcapng',
        captureOffset: null,
        packetNumber: null,
        count: 2,
      },
    ];
    expect(validateCaptureDocument(value)).toEqual(value);
    delete value.diagnostics[0].count;
    expect(() => validateCaptureDocument(value)).toThrow(/count/);
  });

  it('permits unknown optional fields for minor-version compatibility', () => {
    const value = minimal() as Record<string, unknown>;
    value.futureField = { retained: true };
    expect(validateCaptureDocument(value)).toEqual(value);
  });

  it('rejects a non-decimal timestamp string', () => {
    const value = minimal() as { capture: { durationNs: string } };
    value.capture.durationNs = '01';
    expect(() => validateCaptureDocument(value)).toThrow(/durationNs/);
  });

  it('rejects an unknown closed protocol value', () => {
    const value = minimal() as Record<string, unknown>;
    value.packets = [
      {
        id: 'packet-1',
        number: 1,
        timestampNs: '0',
        capturedLength: 0,
        originalLength: 0,
        sourceEndpointId: null,
        destinationEndpointId: null,
        summary: '',
        layers: [
          {
            protocol: 'TELNET',
            label: 'unknown',
            fields: [],
            byteRange: null,
            explanationKey: null,
          },
        ],
        flowId: null,
        analysisFlags: [],
      },
    ];
    expect(() => validateCaptureDocument(value)).toThrow(/protocol/);
  });
});
