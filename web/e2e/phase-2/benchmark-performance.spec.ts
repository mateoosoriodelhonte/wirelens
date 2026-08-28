import { expect, test, type Page } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { arch, cpus, platform, release, totalmem } from 'node:os';
import { BENCHMARK_PROFILES, buildBenchmarkCapture } from '../../../benchmarks/src/fixtures';
import {
  validateBenchmarkResult,
  type BenchmarkResult,
  type MemorySamples,
  type Samples,
} from '../../../benchmarks/src/result';

const RUNS = 3;

function summarize(values: number[]): Samples {
  const ordered = [...values].sort((left, right) => left - right);
  const middle = Math.floor(ordered.length / 2);
  return {
    samples: values,
    median:
      ordered.length % 2 === 0 ? (ordered[middle - 1] + ordered[middle]) / 2 : ordered[middle],
  };
}

interface WasmMeasurement {
  moduleStartupMs: number;
  parseAndSerializationMs: number;
  bridgeDecodeJsonMs: number;
  wasmLinearMemoryPeakBytes: number;
  workerStartupMs: number;
  workerRoundTripMs: number;
}

async function measureWasmInPage(page: Page, bytes: Uint8Array): Promise<WasmMeasurement> {
  return page.evaluate(async (input: number[]) => {
    const bytes = Uint8Array.from(input);
    const startupStart = performance.now();
    const namespace = (await import('/wasm/wirelens.js')) as Record<string, unknown>;
    const factory = namespace.default ?? namespace;
    const module = await (
      factory as (
        options: Record<string, unknown>,
      ) =>
        | Promise<Record<string, unknown> & { HEAPU8: Uint8Array }>
        | (Record<string, unknown> & { HEAPU8: Uint8Array })
    )({
      locateFile: (name: string) => `/wasm/${name}`,
    });
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
    const document = JSON.parse(text);
    const bridgeDecodeJsonMs = performance.now() - decodeStart;
    const workerUrl = URL.createObjectURL(
      new Blob(['self.onmessage = (event) => self.postMessage(event.data);'], {
        type: 'text/javascript',
      }),
    );
    const worker = new Worker(workerUrl);
    const workerStartupStart = performance.now();
    const workerStartupMs = await new Promise<number>((resolve, reject) => {
      worker.onerror = () => reject(new Error('benchmark echo worker failed during startup'));
      worker.onmessage = () => resolve(performance.now() - workerStartupStart);
      worker.postMessage(null);
    });
    const workerRoundTripMs = await new Promise<number>((resolve, reject) => {
      const workerStart = performance.now();
      worker.onerror = () => reject(new Error('benchmark echo worker failed during transport'));
      worker.onmessage = () => resolve(performance.now() - workerStart);
      worker.postMessage(document);
    });
    worker.terminate();
    URL.revokeObjectURL(workerUrl);
    call('wirelens_release', handle);
    return {
      moduleStartupMs,
      parseAndSerializationMs,
      bridgeDecodeJsonMs,
      wasmLinearMemoryPeakBytes: module.HEAPU8.byteLength,
      workerStartupMs,
      workerRoundTripMs,
    };
  }, Array.from(bytes));
}

test('records browser and WASM benchmark measurements without timing thresholds', async ({
  page,
  browser,
  browserName,
}, testInfo) => {
  test.skip(process.env.WIRELENS_BENCHMARK !== '1', 'Opt-in benchmark; set WIRELENS_BENCHMARK=1');
  test.skip(browserName !== 'chromium', 'The reproducible browser benchmark baseline is Chromium');
  test.setTimeout(600_000);
  const fixtures: BenchmarkResult['fixtures'] = [];
  for (const profile of BENCHMARK_PROFILES) {
    const capture = buildBenchmarkCapture(profile);
    const wasm: Record<
      | 'moduleStartupMs'
      | 'parseAndSerializationMs'
      | 'bridgeDecodeJsonMs'
      | 'wasmLinearMemoryPeakBytes',
      number[]
    > = {
      moduleStartupMs: [],
      parseAndSerializationMs: [],
      bridgeDecodeJsonMs: [],
      wasmLinearMemoryPeakBytes: [],
    };
    const workerStartup: number[] = [];
    const workerRoundTrip: number[] = [];
    const firstOverview: number[] = [];
    const filterLatency: number[] = [];
    for (let run = 0; run < RUNS; run += 1) {
      await page.goto('/');
      const start = await page.evaluate(() => performance.now());
      await page.getByLabel('Capture file').setInputFiles({
        name: `${profile.name}.pcap`,
        mimeType: 'application/vnd.tcpdump.pcap',
        buffer: Buffer.from(capture.bytes),
      });
      await expect(page.getByRole('heading', { name: 'Capture overview' })).toBeVisible();
      const overviewEnd = await page.evaluate(() => performance.now());
      firstOverview.push(overviewEnd - start);
      const filterStart = await page.evaluate(() => performance.now());
      await page.getByLabel('Packet filter').fill('udp');
      await expect(
        page.getByRole('region', { name: 'Filter and search' }).getByRole('status'),
      ).toHaveText('No packets match the current filter and search.');
      filterLatency.push((await page.evaluate(() => performance.now())) - filterStart);
      const measurement = await measureWasmInPage(page, capture.bytes);
      wasm.moduleStartupMs.push(measurement.moduleStartupMs);
      wasm.parseAndSerializationMs.push(measurement.parseAndSerializationMs);
      wasm.bridgeDecodeJsonMs.push(measurement.bridgeDecodeJsonMs);
      wasm.wasmLinearMemoryPeakBytes.push(measurement.wasmLinearMemoryPeakBytes);
      workerStartup.push(measurement.workerStartupMs);
      workerRoundTrip.push(measurement.workerRoundTripMs);
    }
    // measureUserAgentSpecificMemory() is a point-in-time snapshot, not a peak.
    // Keep browser memory explicitly unsupported until a bounded sampler exists.
    const memory: MemorySamples = { samples: [], median: null, supported: false };
    fixtures.push({
      profile: profile.name,
      bytes: capture.bytes.byteLength,
      packetCount: profile.packetCount,
      native: null,
      wasm: {
        moduleStartupMs: summarize(wasm.moduleStartupMs),
        parseAndSerializationMs: summarize(wasm.parseAndSerializationMs),
        bridgeDecodeJsonMs: summarize(wasm.bridgeDecodeJsonMs),
        wasmLinearMemoryPeakBytes: {
          samples: wasm.wasmLinearMemoryPeakBytes,
          median: summarize(wasm.wasmLinearMemoryPeakBytes).median,
          supported: true,
        },
        peakMemoryBytes: memory,
      },
      browser: {
        workerStartupMs: summarize(workerStartup),
        workerRoundTripMs: summarize(workerRoundTrip),
        firstOverviewMs: summarize(firstOverview),
        filterLatencyMs: summarize(filterLatency),
        peakMemoryBytes: memory,
      },
    });
  }
  const outputPath = process.env.WIRELENS_BENCHMARK_OUTPUT;
  const commandPrefix = outputPath
    ? `WIRELENS_BENCHMARK=1 WIRELENS_BENCHMARK_OUTPUT=${outputPath}`
    : 'WIRELENS_BENCHMARK=1';
  const browserResult = validateBenchmarkResult({
    schemaVersion: 'wirelens-benchmark/v1',
    metadata: {
      hardware: `${cpus()[0]?.model ?? 'unknown'}; ${cpus().length} logical CPUs; ${Math.round(totalmem() / 1024 ** 3)} GiB RAM; ${arch()}`,
      os: `${platform()} ${release()}`,
      browser: `${testInfo.project.name} ${browser.version()} (Playwright Desktop Chrome emulation)`,
      runtime: `node ${process.version}; ${await page.evaluate(() => navigator.userAgent)}`,
      buildType: 'production',
      command:
        commandPrefix +
        ' pnpm --dir web test:e2e --project=' +
        testInfo.project.name +
        ' e2e/phase-2/benchmark-performance.spec.ts',
      runCount: RUNS,
    },
    fixtures,
  });
  await testInfo.attach('benchmark-result.json', {
    body: Buffer.from(`${JSON.stringify(browserResult, null, 2)}\n`),
    contentType: 'application/json',
  });
  if (outputPath) {
    const absoluteOutputPath = resolve(outputPath);
    await mkdir(dirname(absoluteOutputPath), { recursive: true });
    await writeFile(absoluteOutputPath, `${JSON.stringify(browserResult, null, 2)}\n`);
  }
});
