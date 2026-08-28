import { Ajv2020 } from 'ajv/dist/2020.js';
import { describe, expect, test } from 'vitest';
import schema from '../result.schema.json' with { type: 'json' };
import { validateBenchmarkResult, type BenchmarkResult } from './result.js';

const sample: BenchmarkResult = {
  schemaVersion: 'wirelens-benchmark/v1',
  metadata: {
    hardware: 'test hardware',
    os: 'test os',
    browser: null,
    runtime: 'node test',
    buildType: 'Release',
    command: 'test',
    runCount: 1,
  },
  fixtures: [
    { profile: 'small', bytes: 1, packetCount: 1, native: null, wasm: null, browser: null },
    { profile: 'medium', bytes: 1, packetCount: 1, native: null, wasm: null, browser: null },
    { profile: 'limit-near', bytes: 1, packetCount: 1, native: null, wasm: null, browser: null },
  ],
};

describe('benchmark JSON schema', () => {
  test('validates the result contract', () => {
    const validate = new Ajv2020({ strict: true }).compile(schema);
    expect(validate(validateBenchmarkResult(sample))).toBe(true);
  });

  test('rejects a result with missing command metadata', () => {
    const validate = new Ajv2020({ strict: true }).compile(schema);
    const invalid = structuredClone(sample) as unknown as Record<string, unknown>;
    delete (invalid.metadata as Record<string, unknown>).command;
    expect(validate(invalid)).toBe(false);
  });

  test('accepts a native peak-memory sample', () => {
    const validate = new Ajv2020({ strict: true }).compile(schema);
    const value = structuredClone(sample);
    value.fixtures[0].native = {
      parseMs: { samples: [1], median: 1 },
      jsonSerializationMs: { samples: [2], median: 2 },
      peakMemoryBytes: { samples: [7], median: 7, supported: true },
    };
    expect(validate(validateBenchmarkResult(value))).toBe(true);
  });
});
