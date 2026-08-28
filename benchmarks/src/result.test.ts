import { describe, expect, test } from 'vitest';
import { validateBenchmarkResult, type BenchmarkResult } from './result.js';

const validResult: BenchmarkResult = {
  schemaVersion: 'wirelens-benchmark/v1',
  metadata: {
    hardware: 'test hardware',
    os: 'test os',
    browser: null,
    runtime: 'node test',
    buildType: 'Release',
    command: 'pnpm benchmark',
    runCount: 3,
  },
  fixtures: [
    {
      profile: 'small',
      bytes: 214,
      packetCount: 3,
      native: {
        parseMs: { samples: [1, 2, 3], median: 2 },
        jsonSerializationMs: { samples: [1, 2, 3], median: 2 },
        peakMemoryBytes: { samples: [10, 11, 12], median: 11, supported: true },
      },
      wasm: {
        moduleStartupMs: { samples: [2, 3, 4], median: 3 },
        parseAndSerializationMs: { samples: [2, 3, 4], median: 3 },
        bridgeDecodeJsonMs: { samples: [3, 4, 5], median: 4 },
        wasmLinearMemoryPeakBytes: { samples: [20, 21, 22], median: 21, supported: true },
        peakMemoryBytes: { samples: [], median: null, supported: false },
      },
      browser: null,
    },
    { profile: 'medium', bytes: 1, packetCount: 1, native: null, wasm: null, browser: null },
    { profile: 'limit-near', bytes: 1, packetCount: 1, native: null, wasm: null, browser: null },
  ],
};

describe('benchmark result validation', () => {
  test('accepts the complete result shape', () => {
    expect(validateBenchmarkResult(validResult)).toEqual(validResult);
  });

  test('rejects missing reproducibility metadata', () => {
    const value = structuredClone(validResult) as unknown as Record<string, unknown>;
    delete (value.metadata as Record<string, unknown>).command;
    expect(() => validateBenchmarkResult(value)).toThrow(/metadata.command/);
  });

  test('rejects a sample count that does not match runCount', () => {
    const value = structuredClone(validResult);
    value.fixtures[0].native!.parseMs.samples = [1, 2];
    expect(() => validateBenchmarkResult(value)).toThrow(/runCount/);
  });

  test('rejects unsupported memory measurements with samples', () => {
    const value = structuredClone(validResult);
    value.fixtures[0].wasm!.peakMemoryBytes = {
      samples: [1],
      median: 1,
      supported: false,
    };
    expect(() => validateBenchmarkResult(value)).toThrow(/supported/);
  });

  test('rejects a duplicate or missing complete profile', () => {
    const value = structuredClone(validResult);
    value.fixtures.push({ ...value.fixtures[0], profile: 'medium' });
    expect(() => validateBenchmarkResult(value)).toThrow(/small, medium, and limit-near/);
  });

  test('rejects a median that does not match raw samples', () => {
    const value = structuredClone(validResult);
    value.fixtures[0].native!.parseMs.median = 9;
    expect(() => validateBenchmarkResult(value)).toThrow(/raw samples/);
  });

  test('recomputes the median after sorting unsorted samples', () => {
    const value = structuredClone(validResult);
    value.fixtures[0].native!.parseMs = { samples: [3, 1, 2], median: 2 };
    expect(validateBenchmarkResult(value).fixtures[0].native!.parseMs.median).toBe(2);
  });
});
