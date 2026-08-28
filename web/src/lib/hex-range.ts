import type { ByteRange } from '@wirelens/schema';

export type ByteRangeValidation =
  { kind: 'valid'; start: number; endExclusive: number } | { kind: 'none' } | { kind: 'invalid' };

export function validateByteRange(
  range: ByteRange | null | undefined,
  byteLength: number,
): ByteRangeValidation {
  if (range === null || range === undefined) return { kind: 'none' };
  if (!Number.isSafeInteger(byteLength) || byteLength < 0) return { kind: 'invalid' };

  const { captureOffset, packetOffset, length } = range;
  if (
    !Number.isSafeInteger(captureOffset) ||
    captureOffset < 0 ||
    !Number.isSafeInteger(packetOffset) ||
    packetOffset < 0 ||
    !Number.isSafeInteger(length) ||
    length < 0
  ) {
    return { kind: 'invalid' };
  }
  if (length === 0) return { kind: 'none' };
  if (packetOffset > byteLength || length > byteLength - packetOffset) {
    return { kind: 'invalid' };
  }
  return { kind: 'valid', start: packetOffset, endExclusive: packetOffset + length };
}
