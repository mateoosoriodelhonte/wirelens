import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { runWasmBenchmark } from './wasm.ts';

const args = process.argv.slice(2).filter((value) => value !== '--');
const modulePath = args[0];
if (!modulePath) {
  console.error('Usage: pnpm --dir benchmarks run-wasm -- WEBASSEMBLY_MODULE [OUTPUT]');
  process.exitCode = 2;
} else {
  const output = args[1] ?? 'results/wasm.json';
  const runs = Number(process.env.WIRELENS_BENCHMARK_RUNS ?? 10);
  const warmup = Number(process.env.WIRELENS_BENCHMARK_WARMUP ?? 2);
  const buildType = process.env.WIRELENS_BENCHMARK_BUILD_TYPE ?? 'unknown';
  const result = await runWasmBenchmark({
    modulePath,
    runs,
    warmup,
    buildType,
    command:
      `WIRELENS_BENCHMARK_RUNS=${runs} WIRELENS_BENCHMARK_WARMUP=${warmup} ` +
      `WIRELENS_BENCHMARK_BUILD_TYPE=${buildType} pnpm --dir benchmarks run-wasm -- ` +
      `${modulePath} ${output}`,
  });
  await mkdir(dirname(output), { recursive: true });
  await writeFile(output, `${JSON.stringify(result, null, 2)}\n`);
  console.log(`Wrote benchmark result to ${output}`);
}
