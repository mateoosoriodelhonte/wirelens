#!/usr/bin/env node

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readdir, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { format } from 'prettier';

const execFileAsync = promisify(execFile);
const scriptPath = fileURLToPath(import.meta.url);
const repoRoot = resolve(dirname(scriptPath), '..');

async function main(argv) {
  if (argv.length !== 1) throw new Error('Usage: generate-goldens.mjs <native-cli>');
  const nativeCli = isAbsolute(argv[0]) ? argv[0] : resolve(repoRoot, argv[0]);
  const generated = resolve(repoRoot, 'fixtures/generated');
  const expected = resolve(repoRoot, 'fixtures/expected');
  const fixtures = (await readdir(generated))
    .filter((name) => /\.(pcap|pcapng)$/u.test(name))
    .sort();
  for (const fixture of fixtures) {
    const { stdout } = await execFileAsync(nativeCli, [resolve(generated, fixture), '--json'], {
      encoding: 'utf8',
    });
    JSON.parse(stdout);
    const golden = await format(stdout, {
      parser: 'json',
      printWidth: 100,
      objectWrap: 'preserve',
    });
    await writeFile(resolve(expected, `${fixture}.capture.json`), golden);
    if (fixture === 'tcp-handshake.pcap') {
      await writeFile(resolve(expected, 'tcp-handshake.capture.json'), golden);
    }
  }
  process.stdout.write(`Generated ${fixtures.length} capture goldens.\n`);
}

main(process.argv.slice(2)).catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
