// @vitest-environment node
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const repoRoot = resolve(import.meta.dirname, '../../../..');
const nativeCli = resolve(repoRoot, 'build/native-debug/cli/wirelens');
const fixture = resolve(repoRoot, 'fixtures/generated/tcp-handshake.pcap');
const wasmModule = resolve(repoRoot, 'web/static/wasm/wirelens.js');
const golden = resolve(repoRoot, 'fixtures/expected/tcp-handshake.capture.json');

describe('native and WebAssembly contract parity', () => {
  it('runs both real parser artifacts against the same fixture', () => {
    const missing = [nativeCli, fixture, wasmModule, wasmModule.replace(/\.js$/, '.wasm')].filter(
      (path) => !existsSync(path),
    );
    if (missing.length > 0) {
      throw new Error(
        `Contract parity artifacts are missing: ${missing.join(', ')}. ` +
          'Build native-debug and WebAssembly first (see scripts/build-wasm.sh).',
      );
    }
    const output = execFileSync(
      process.execPath,
      ['scripts/check-contract-parity.mjs', nativeCli, fixture, wasmModule, golden],
      { cwd: repoRoot, encoding: 'utf8' },
    );
    expect(output).toMatch(/Contract parity: .*match/);
  });
});
