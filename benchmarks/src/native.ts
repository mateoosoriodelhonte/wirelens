import { execFileSync } from 'node:child_process';
import { mkdir, rm, writeFile } from 'node:fs/promises';
import { arch, cpus, platform, release, tmpdir, totalmem } from 'node:os';
import { join } from 'node:path';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { BENCHMARK_PROFILES, buildBenchmarkCapture } from './fixtures.ts';
import {
  BENCHMARK_RESULT_SCHEMA,
  type BenchmarkFixtureResult,
  type BenchmarkResult,
  type Samples,
  validateBenchmarkResult,
} from './result.ts';

interface NativeOutput {
  bytes: number;
  packetCount: number;
  jsonBytes: number;
  parseMs: number[];
  jsonSerializationMs: number[];
  peakMemoryBytes: number[];
  peakMemorySupported: boolean;
}

export interface NativeBenchmarkOptions {
  executable: string;
  runs?: number;
  warmup?: number;
  buildType?: string;
  command?: string;
}

function median(samples: readonly number[]): number | null {
  if (samples.length === 0) return null;
  const ordered = [...samples].sort((left, right) => left - right);
  const middle = Math.floor(ordered.length / 2);
  return ordered.length % 2 === 0 ? (ordered[middle - 1] + ordered[middle]) / 2 : ordered[middle];
}

function samples(values: number[]): Samples {
  return { samples: values, median: median(values) };
}

function runNative(
  executable: string,
  capturePath: string,
  runs: number,
  warmup: number,
): NativeOutput {
  const output = execFileSync(
    executable,
    ['--capture', capturePath, '--runs', String(runs), '--warmup', String(warmup)],
    { encoding: 'utf8' },
  );
  const parsed = JSON.parse(output) as NativeOutput;
  if (
    !parsed ||
    parsed.packetCount < 1 ||
    !Array.isArray(parsed.parseMs) ||
    parsed.parseMs.length !== runs
  )
    throw new Error(`native benchmark returned an invalid sample set for ${capturePath}`);
  return parsed;
}

/** Run all generated profiles and return a schema-validated, reproducible native report. */
export async function runNativeBenchmark(
  options: NativeBenchmarkOptions,
): Promise<BenchmarkResult> {
  const runs = options.runs ?? 10;
  const warmup = options.warmup ?? 2;
  if (!Number.isSafeInteger(runs) || runs < 1) throw new RangeError('runs must be positive');
  const temporaryDirectory = join(tmpdir(), `wirelens-benchmark-${randomUUID()}`);
  const fixtures: BenchmarkFixtureResult[] = [];
  try {
    for (const profile of BENCHMARK_PROFILES) {
      const capture = buildBenchmarkCapture(profile);
      const capturePath = join(temporaryDirectory, `${profile.name}.pcap`);
      await mkdir(temporaryDirectory, { recursive: true });
      await writeFile(capturePath, capture.bytes);
      const native = runNative(options.executable, capturePath, runs, warmup);
      fixtures.push({
        profile: profile.name,
        bytes: capture.bytes.byteLength,
        packetCount: capture.packetCount,
        native: {
          parseMs: samples(native.parseMs),
          jsonSerializationMs: samples(native.jsonSerializationMs),
          peakMemoryBytes: {
            ...samples(native.peakMemorySupported ? native.peakMemoryBytes : []),
            supported: native.peakMemorySupported,
          },
        },
        wasm: null,
        browser: null,
      });
    }
  } finally {
    // The generated capture is disposable benchmark input. Keep no result data in the repo.
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
  const result: BenchmarkResult = {
    schemaVersion: BENCHMARK_RESULT_SCHEMA,
    metadata: {
      hardware: `${cpus()[0]?.model ?? 'unknown'}; ${cpus().length} logical CPUs; ${Math.round(totalmem() / 1024 ** 3)} GiB RAM; ${arch()}`,
      os: `${platform()} ${release()}`.trim(),
      browser: null,
      runtime: `node ${process.version}`,
      buildType: options.buildType ?? 'unknown',
      command: options.command ?? `${options.executable} --runs ${runs} --warmup ${warmup}`,
      runCount: runs,
    },
    fixtures,
  };
  return validateBenchmarkResult(result);
}

export async function writeNativeBenchmarkResult(
  options: NativeBenchmarkOptions,
  outputPath: string,
): Promise<void> {
  const result = await runNativeBenchmark(options);
  await mkdir(dirname(outputPath), { recursive: true });
  await writeFile(outputPath, `${JSON.stringify(result, null, 2)}\n`);
}
