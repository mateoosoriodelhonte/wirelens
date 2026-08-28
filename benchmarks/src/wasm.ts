import { execPath } from 'node:process';
import { cpus, platform, release } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { BENCHMARK_PROFILES, buildBenchmarkCapture } from './fixtures.ts';
import {
  BENCHMARK_RESULT_SCHEMA,
  type BenchmarkResult,
  type Samples,
  validateBenchmarkResult,
} from './result.ts';

interface WasmOutput {
  moduleStartupMs: number;
  parseAndSerializationMs: number;
  bridgeDecodeJsonMs: number;
  wasmLinearMemoryPeakBytes: number;
}

export interface WasmBenchmarkOptions {
  modulePath: string;
  runs?: number;
  warmup?: number;
  buildType?: string;
  command?: string;
}

function median(values: readonly number[]): number | null {
  if (values.length === 0) return null;
  const ordered = [...values].sort((left, right) => left - right);
  const middle = Math.floor(ordered.length / 2);
  return values.length % 2 === 0 ? (ordered[middle - 1] + ordered[middle]) / 2 : ordered[middle];
}

function samples(values: number[]): Samples {
  return { samples: values, median: median(values) };
}

async function runWasmModule(modulePath: string, bytes: Uint8Array): Promise<WasmOutput> {
  const startupStart = performance.now();
  const namespace = (await import(pathToFileURL(modulePath).href)) as Record<string, unknown>;
  const factory = namespace.default ?? namespace;
  const module = await (
    factory as (
      options: Record<string, unknown>,
    ) =>
      | Promise<Record<string, unknown> & { HEAPU8: Uint8Array }>
      | (Record<string, unknown> & { HEAPU8: Uint8Array })
  )({ locateFile: (name: string) => join(modulePath, '..', name) });
  const moduleStartupMs = performance.now() - startupStart;
  const call = (name: string, ...args: number[]): number => {
    const fn = module[name] ?? module[`_${name}`];
    if (typeof fn !== 'function') throw new Error(`missing WASM export ${name}`);
    return (fn as (...values: number[]) => number)(...args);
  };
  const pointer = call('wirelens_alloc', bytes.byteLength);
  if (!pointer) throw new Error('WASM allocation failed');
  module.HEAPU8.set(bytes, pointer);
  const parseStart = performance.now();
  const handle = call('wirelens_parse_owned', pointer, bytes.byteLength);
  const parseAndSerializationMs = performance.now() - parseStart;
  if (!handle || !call('wirelens_result_ok', handle)) throw new Error('WASM parse failed');
  const decodeStart = performance.now();
  const jsonPointer = call('wirelens_result_data', handle);
  const jsonSize = call('wirelens_result_size', handle);
  const text = new TextDecoder().decode(
    module.HEAPU8.subarray(jsonPointer, jsonPointer + jsonSize),
  );
  JSON.parse(text);
  const bridgeDecodeJsonMs = performance.now() - decodeStart;
  const wasmLinearMemoryPeakBytes = module.HEAPU8.byteLength;
  call('wirelens_release', handle);
  return {
    moduleStartupMs,
    parseAndSerializationMs,
    bridgeDecodeJsonMs,
    wasmLinearMemoryPeakBytes,
  };
}

/** Run all profiles through the Emscripten module without passing bytes through a browser. */
export async function runWasmBenchmark(options: WasmBenchmarkOptions): Promise<BenchmarkResult> {
  const runs = options.runs ?? 10;
  const warmup = options.warmup ?? 2;
  if (!Number.isSafeInteger(runs) || runs < 1) throw new RangeError('runs must be positive');
  if (!Number.isSafeInteger(warmup) || warmup < 0)
    throw new RangeError('warmup must be non-negative');
  const fixtures: BenchmarkResult['fixtures'] = [];
  for (const profile of BENCHMARK_PROFILES) {
    const capture = buildBenchmarkCapture(profile);
    const moduleStartupMs: number[] = [];
    const parseAndSerializationMs: number[] = [];
    const bridgeDecodeJsonMs: number[] = [];
    const wasmLinearMemoryPeakBytes: number[] = [];
    for (let index = 0; index < warmup; index += 1)
      await runWasmModule(options.modulePath, capture.bytes);
    for (let index = 0; index < runs; index += 1) {
      const measurement = await runWasmModule(options.modulePath, capture.bytes);
      moduleStartupMs.push(measurement.moduleStartupMs);
      parseAndSerializationMs.push(measurement.parseAndSerializationMs);
      bridgeDecodeJsonMs.push(measurement.bridgeDecodeJsonMs);
      wasmLinearMemoryPeakBytes.push(measurement.wasmLinearMemoryPeakBytes);
    }
    fixtures.push({
      profile: profile.name,
      bytes: capture.bytes.byteLength,
      packetCount: capture.packetCount,
      native: null,
      wasm: {
        moduleStartupMs: samples(moduleStartupMs),
        parseAndSerializationMs: samples(parseAndSerializationMs),
        bridgeDecodeJsonMs: samples(bridgeDecodeJsonMs),
        wasmLinearMemoryPeakBytes: {
          ...samples(wasmLinearMemoryPeakBytes),
          supported: true,
        },
        peakMemoryBytes: { samples: [], median: null, supported: false },
      },
      browser: null,
    });
  }
  return validateBenchmarkResult({
    schemaVersion: BENCHMARK_RESULT_SCHEMA,
    metadata: {
      hardware: `${cpus()[0]?.model ?? 'unknown'}; ${cpus().length} logical CPUs`,
      os: `${platform()} ${release()}`,
      browser: null,
      runtime: `node ${process.version}; ${execPath}`,
      buildType: options.buildType ?? 'unknown',
      command: options.command ?? `node --module ${options.modulePath} --runs ${runs}`,
      runCount: runs,
    },
    fixtures,
  });
}
