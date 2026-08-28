export const BENCHMARK_RESULT_SCHEMA = 'wirelens-benchmark/v1' as const;

export interface Samples {
  samples: number[];
  median: number | null;
}

export interface MemorySamples extends Samples {
  supported: boolean;
}

export interface BenchmarkMetadata {
  hardware: string;
  os: string;
  browser: string | null;
  runtime: string;
  buildType: string;
  command: string;
  runCount: number;
}

export interface BenchmarkFixtureResult {
  profile: 'small' | 'medium' | 'limit-near';
  bytes: number;
  packetCount: number;
  native: {
    parseMs: Samples;
    jsonSerializationMs: Samples;
    peakMemoryBytes: MemorySamples;
  } | null;
  wasm: {
    moduleStartupMs: Samples;
    parseAndSerializationMs: Samples;
    bridgeDecodeJsonMs: Samples;
    wasmLinearMemoryPeakBytes: MemorySamples;
    peakMemoryBytes: MemorySamples;
  } | null;
  browser: {
    workerRoundTripMs: Samples;
    firstOverviewMs: Samples;
    filterLatencyMs: Samples;
    peakMemoryBytes: MemorySamples;
  } | null;
}

export interface BenchmarkResult {
  schemaVersion: typeof BENCHMARK_RESULT_SCHEMA;
  metadata: BenchmarkMetadata;
  fixtures: BenchmarkFixtureResult[];
}

function fail(path: string, message: string): never {
  throw new TypeError(`${path}: ${message}`);
}

function object(value: unknown, path: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(path, 'must be an object');
  return value as Record<string, unknown>;
}

function string(value: unknown, path: string): string {
  if (typeof value !== 'string' || value.length === 0) fail(path, 'must be a non-empty string');
  return value;
}

function nonNegativeInteger(value: unknown, path: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0)
    fail(path, 'must be a non-negative safe integer');
  return value;
}

function sampleSet(value: unknown, path: string, runCount: number): Samples {
  const source = object(value, path);
  if (!Array.isArray(source.samples) || source.samples.length !== runCount)
    fail(`${path}.samples`, `must contain exactly runCount (${runCount}) values`);
  const samples = source.samples.map((sample, index) => {
    if (typeof sample !== 'number' || !Number.isFinite(sample) || sample < 0)
      fail(`${path}.samples[${index}]`, 'must be a finite non-negative number');
    return sample;
  });
  if (
    source.median !== null &&
    (typeof source.median !== 'number' || !Number.isFinite(source.median) || source.median < 0)
  )
    fail(`${path}.median`, 'must be a finite number or null');
  const ordered = [...samples].sort((left, right) => left - right);
  const expectedMedian =
    samples.length === 0
      ? null
      : samples.length % 2 === 0
        ? (ordered[samples.length / 2 - 1] + ordered[samples.length / 2]) / 2
        : ordered[Math.floor(samples.length / 2)];
  if (source.median !== expectedMedian) fail(`${path}.median`, 'does not match the raw samples');
  return { samples, median: source.median as number | null };
}

function memorySet(value: unknown, path: string, runCount: number): MemorySamples {
  const source = object(value, path);
  if (typeof source.supported !== 'boolean') fail(`${path}.supported`, 'must be boolean');
  if (!source.supported && Array.isArray(source.samples) && source.samples.length !== 0)
    fail(`${path}.supported`, 'false requires an empty samples array');
  const samples = sampleSet(source, path, source.supported ? runCount : 0);
  if (!source.supported && samples.median !== null)
    fail(`${path}.median`, 'must be null when unsupported');
  return { ...samples, supported: source.supported };
}

function metricSet(value: unknown, path: string, runCount: number): void {
  sampleSet(value, path, runCount);
}

export function validateBenchmarkResult(value: unknown): BenchmarkResult {
  const root = object(value, 'result');
  if (root.schemaVersion !== BENCHMARK_RESULT_SCHEMA)
    fail('result.schemaVersion', `must equal ${BENCHMARK_RESULT_SCHEMA}`);
  const metadata = object(root.metadata, 'result.metadata');
  const hardware = string(metadata.hardware, 'result.metadata.hardware');
  const os = string(metadata.os, 'result.metadata.os');
  const buildType = string(metadata.buildType, 'result.metadata.buildType');
  const runtime = string(metadata.runtime, 'result.metadata.runtime');
  const command = string(metadata.command, 'result.metadata.command');
  const runCount = metadata.runCount;
  if (typeof runCount !== 'number' || !Number.isSafeInteger(runCount) || runCount < 1)
    fail('result.metadata.runCount', 'must be a positive safe integer');
  if (metadata.browser !== null && typeof metadata.browser !== 'string')
    fail('result.metadata.browser', 'must be a string or null');
  if (!Array.isArray(root.fixtures) || root.fixtures.length === 0)
    fail('result.fixtures', 'must be a non-empty array');

  const fixtures = root.fixtures.map((raw, index) => {
    const fixture = object(raw, `result.fixtures[${index}]`);
    if (!['small', 'medium', 'limit-near'].includes(fixture.profile as string))
      fail(`result.fixtures[${index}].profile`, 'must be a benchmark profile');
    const bytes = nonNegativeInteger(fixture.bytes, `result.fixtures[${index}].bytes`);
    const packetCount = nonNegativeInteger(
      fixture.packetCount,
      `result.fixtures[${index}].packetCount`,
    );
    const requiredMetrics: Record<'native' | 'wasm' | 'browser', readonly string[]> = {
      native: ['parseMs', 'jsonSerializationMs', 'peakMemoryBytes'],
      wasm: [
        'moduleStartupMs',
        'parseAndSerializationMs',
        'bridgeDecodeJsonMs',
        'wasmLinearMemoryPeakBytes',
        'peakMemoryBytes',
      ],
      browser: ['workerRoundTripMs', 'firstOverviewMs', 'filterLatencyMs', 'peakMemoryBytes'],
    };
    for (const side of ['native', 'wasm', 'browser'] as const) {
      const valueForSide = fixture[side];
      if (valueForSide === null) continue;
      const metrics = object(valueForSide, `result.fixtures[${index}].${side}`);
      for (const required of requiredMetrics[side]) {
        if (!(required in metrics))
          fail(`result.fixtures[${index}].${side}.${required}`, 'is required');
      }
      for (const [name, metric] of Object.entries(metrics)) {
        if (name === 'peakMemoryBytes')
          memorySet(metric, `result.fixtures[${index}].${side}.${name}`, runCount);
        else metricSet(metric, `result.fixtures[${index}].${side}.${name}`, runCount);
      }
    }
    return {
      profile: fixture.profile as BenchmarkFixtureResult['profile'],
      bytes,
      packetCount,
      native: fixture.native as BenchmarkFixtureResult['native'],
      wasm: fixture.wasm as BenchmarkFixtureResult['wasm'],
      browser: fixture.browser as BenchmarkFixtureResult['browser'],
    };
  });
  const profiles = fixtures.map((fixture) => fixture.profile);
  const expectedProfiles = ['small', 'medium', 'limit-near'];
  if (
    profiles.length !== expectedProfiles.length ||
    new Set(profiles).size !== profiles.length ||
    expectedProfiles.some(
      (profile) => !profiles.includes(profile as BenchmarkFixtureResult['profile']),
    )
  )
    fail('result.fixtures', 'must contain small, medium, and limit-near exactly once');
  return {
    schemaVersion: BENCHMARK_RESULT_SCHEMA,
    metadata: {
      hardware,
      os,
      browser: metadata.browser as string | null,
      runtime,
      buildType,
      command,
      runCount,
    },
    fixtures,
  };
}
