import { writeNativeBenchmarkResult } from './native.ts';

const args = process.argv.slice(2).filter((value) => value !== '--');
const executable = args[0];
if (!executable) {
  console.error('Usage: pnpm --dir benchmarks run-native -- EXECUTABLE [OUTPUT]');
  process.exitCode = 2;
} else {
  const output = args[1] ?? 'results/native.json';
  const runs = Number(process.env.WIRELENS_BENCHMARK_RUNS ?? 10);
  const warmup = Number(process.env.WIRELENS_BENCHMARK_WARMUP ?? 2);
  const buildType = process.env.WIRELENS_BENCHMARK_BUILD_TYPE ?? 'unknown';
  await writeNativeBenchmarkResult(
    {
      executable,
      runs,
      warmup,
      buildType,
      command:
        `WIRELENS_BENCHMARK_RUNS=${runs} WIRELENS_BENCHMARK_WARMUP=${warmup} ` +
        `WIRELENS_BENCHMARK_BUILD_TYPE=${buildType} pnpm --dir benchmarks run-native -- ` +
        `${executable} ${output}`,
    },
    output,
  );
  console.log(`Wrote benchmark result to ${output}`);
}
