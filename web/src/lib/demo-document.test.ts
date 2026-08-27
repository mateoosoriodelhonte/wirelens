import { describe, expect, it } from 'vitest';
import { validateCaptureDocument } from '@wirelens/schema';
import { demoDocument } from './demo-document';

const keys = (value: object) => Object.keys(value).sort();

describe('demoDocument contract shape', () => {
  it('validates against the shared runtime schema', () => {
    expect(validateCaptureDocument(demoDocument)).toBe(demoDocument);
  });

  it('contains only the transport fields defined by the Task 2 contract', () => {
    expect(keys(demoDocument)).toEqual([
      'capture',
      'contractVersion',
      'diagnostics',
      'endpoints',
      'flows',
      'packets',
      'schema',
    ]);
    expect(keys(demoDocument.endpoints[0])).toEqual(['address', 'addressFamily', 'id', 'port']);
    expect(keys(demoDocument.packets[0])).toEqual([
      'analysisFlags',
      'capturedLength',
      'destinationEndpointId',
      'flowId',
      'id',
      'layers',
      'number',
      'originalLength',
      'sourceEndpointId',
      'summary',
      'timestampNs',
    ]);
    expect(keys(demoDocument.packets[0].layers[0])).toEqual([
      'byteRange',
      'explanationKey',
      'fields',
      'label',
      'protocol',
    ]);
    expect(keys(demoDocument.packets[0].layers[0].fields[0])).toEqual([
      'byteRange',
      'explanationKey',
      'name',
      'value',
    ]);
    expect(keys(demoDocument.flows[0])).toEqual([
      'capturedBytes',
      'clientEndpointId',
      'endTimestampNs',
      'events',
      'handshake',
      'id',
      'originalBytes',
      'packetNumbers',
      'protocol',
      'serverEndpointId',
      'startTimestampNs',
      'termination',
    ]);
    expect(keys(demoDocument.flows[0].events[0])).toEqual(['label', 'packetNumber']);
  });
});
