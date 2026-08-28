import { describe, expect, it } from 'vitest';
import { validateByteRange } from './hex-range';

describe('validateByteRange', () => {
  it('accepts a range that ends at the buffer boundary', () => {
    expect(validateByteRange({ captureOffset: 0, packetOffset: 12, length: 4 }, 16)).toEqual({
      kind: 'valid',
      start: 12,
      endExclusive: 16,
    });
  });

  it('accepts offset equal to the buffer length only when the range is non-empty', () => {
    expect(validateByteRange({ captureOffset: 0, packetOffset: 16, length: 1 }, 16).kind).toBe(
      'invalid',
    );
  });

  it('rejects zero length and absent ranges without producing a selection', () => {
    expect(validateByteRange({ captureOffset: 0, packetOffset: 3, length: 0 }, 16).kind).toBe(
      'none',
    );
    expect(validateByteRange(null, 16).kind).toBe('none');
  });

  it('uses subtraction for overflow-safe bounds checks', () => {
    expect(
      validateByteRange(
        {
          captureOffset: 0,
          packetOffset: Number.MAX_SAFE_INTEGER,
          length: Number.MAX_SAFE_INTEGER,
        },
        16,
      ).kind,
    ).toBe('invalid');
    expect(validateByteRange({ captureOffset: 0, packetOffset: 15, length: 2 }, 16).kind).toBe(
      'invalid',
    );
  });

  it('rejects non-integer and negative hostile values', () => {
    expect(validateByteRange({ captureOffset: 0, packetOffset: -1, length: 1 }, 16).kind).toBe(
      'invalid',
    );
    expect(validateByteRange({ captureOffset: 0, packetOffset: 1.5, length: 1 }, 16).kind).toBe(
      'invalid',
    );
    expect(
      validateByteRange({ captureOffset: 0, packetOffset: 1, length: Infinity }, 16).kind,
    ).toBe('invalid');
  });
});
