import { writeNativeBenchmarkResult } from './native.ts';

const args = process.argv.slice(2).filter((value) => value !== '--');
const executable = args[0];
if (!executable) {
  console.error('Usage: pnpm --dir benchmarks run-native -- EXECUTABLE [OUTPUT]');
  process.exitCode = 2;
} else {
  const output = args[1] ?? 'results/native.json';
  await writeNativeBenchmarkResult(
    {
      executable,
      runs: Number(process.env.WIRELENS_BENCHMARK_RUNS ?? 10),
      warmup: Number(process.env.WIRELENS_BENCHMARK_WARMUP ?? 2),
      buildType: process.env.WIRELENS_BENCHMARK_BUILD_TYPE ?? 'unknown',
      command: `pnpm --dir benchmarks run-native -- ${executable} ${output}`,
    },
    output,
  );
  console.log(`Wrote benchmark result to ${output}`);
}
