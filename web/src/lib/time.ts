const DECIMAL_NS = /^(0|[1-9][0-9]*)$/;
const NS_PER_MS = 1_000_000n;

function parseNanoseconds(value: string): bigint {
  if (!DECIMAL_NS.test(value))
    throw new RangeError('Expected a non-negative decimal nanosecond string.');
  return BigInt(value);
}

export function formatMilliseconds(durationNs: string): string {
  const nanoseconds = parseNanoseconds(durationNs);
  const milliseconds = nanoseconds / NS_PER_MS;
  const remainder = nanoseconds % NS_PER_MS;
  if (remainder === 0n) return `${milliseconds} ms`;
  const fraction = remainder.toString().padStart(6, '0').replace(/0+$/, '');
  return `${milliseconds}.${fraction} ms`;
}

export function elapsedMilliseconds(startNs: string | null, endNs: string | null): string {
  if (startNs === null || endNs === null) return '—';
  const start = parseNanoseconds(startNs);
  const end = parseNanoseconds(endNs);
  return formatMilliseconds((end >= start ? end - start : 0n).toString());
}
