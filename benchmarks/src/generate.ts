import { writeBenchmarkCaptures } from './fixtures.ts';

const directory = process.argv.slice(2).find((value) => value !== '--') ?? 'generated';
await writeBenchmarkCaptures(directory);
console.log(`Generated benchmark captures in ${directory}`);
