import { describe, expect, it } from 'vitest';
import { validateCaptureDocument } from './validate.js';

describe('validateCaptureDocument', () => {
  const minimal = () => ({
    schema: 'wirelens.capture',
    contractVersion: '1.0.0',
    capture: {
      format: 'pcap',
      timestampResolution: 'microseconds',
      packetCount: 0,
      capturedBytes: 0,
      originalBytes: 0,
      startTimestampNs: null,
      endTimestampNs: null,
      durationNs: '0',
    },
    endpoints: [],
    packets: [],
    flows: [],
    diagnostics: [],
  });

  it('rejects an unknown contract major version', () => {
    expect(() =>
      validateCaptureDocument({ schema: 'wirelens.capture', contractVersion: '2.0.0' }),
    ).toThrow(/contractVersion/);
  });

  it('accepts the minimal Phase 1 document', () => {
    const value = minimal();
    expect(validateCaptureDocument(value)).toEqual(value);
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
