import { createHash } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { BENCHMARK_PROFILES, buildBenchmarkCapture } from './fixtures.js';

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

const EXPECTED = {
  small: {
    bytes: 234,
    sha256: '29319f657046bc75098c32b3373d2696405950412697d6b2393ff28fd3681a27',
  },
  medium: {
    bytes: 71_704,
    sha256: '2937ad1e466a23bfd9dd7e38164167c40eae237d320fce2aae0c01b75da6b354',
  },
  'limit-near': {
    bytes: 1_966_074,
    sha256: 'd89a133e50faae94e6e2026919c7318911225ad10ff3eafb6c99b38c5ea4b442',
  },
} as const;

describe('benchmark capture profiles', () => {
  for (const profile of BENCHMARK_PROFILES) {
    test(`${profile.name} is deterministic`, () => {
      const first = buildBenchmarkCapture(profile);
      const second = buildBenchmarkCapture(profile);

      expect(first.packetCount).toBe(profile.packetCount);
      expect(second.packetCount).toBe(profile.packetCount);
      expect(first.bytes).toEqual(second.bytes);
      expect(first.bytes.byteLength).toBe(EXPECTED[profile.name].bytes);
      expect(sha256(first.bytes)).toBe(EXPECTED[profile.name].sha256);
      expect(sha256(first.bytes)).toBe(sha256(second.bytes));
    }, 15_000);
  }

  test('profiles stay below the configured capture limit', () => {
    for (const profile of BENCHMARK_PROFILES) {
      expect(buildBenchmarkCapture(profile).bytes.byteLength).toBeLessThanOrEqual(64 * 1024 * 1024);
    }
  });
});
