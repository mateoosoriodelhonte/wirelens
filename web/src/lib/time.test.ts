import { describe, expect, it } from 'vitest';
import { elapsedMilliseconds } from './time';

describe('elapsedMilliseconds', () => {
  it('keeps exact 10 ms differences above Number safe integer range', () => {
    const start = '9007199254740993';
    const end = '9007199264740993';
    expect(elapsedMilliseconds(start, end)).toBe('10 ms');
  });
});
