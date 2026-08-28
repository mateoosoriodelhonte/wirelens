import { writeBenchmarkCaptures } from './fixtures.ts';

const directory = process.argv[2] ?? 'benchmarks/generated';
await writeBenchmarkCaptures(directory);
console.log(`Generated benchmark captures in ${directory}`);
