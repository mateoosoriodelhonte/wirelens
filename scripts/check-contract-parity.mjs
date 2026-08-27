#!/usr/bin/env node

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { readdir, readFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Ajv2020 } from '../schema/node_modules/ajv/dist/2020.js';

const execFileAsync = promisify(execFile);
const scriptPath = fileURLToPath(import.meta.url);
const repoRoot = resolve(dirname(scriptPath), '..');
const schemaPath = resolve(repoRoot, 'schema/capture.schema.json');

const jsonSchema = JSON.parse(await readFile(schemaPath, 'utf8'));
const ajv = new Ajv2020({ allErrors: true, strict: true });
const validate = ajv.compile(jsonSchema);

function valueDescription(value) {
  if (value === undefined) return 'missing';
  if (typeof value === 'string') return JSON.stringify(value);
  return JSON.stringify(value);
}

function childPath(path, key) {
  return typeof key === 'number' ? `${path}[${key}]` : `${path}.${key}`;
}

function findMismatch(expected, actual, path = '$') {
  if (Object.is(expected, actual)) return null;
  if (typeof expected !== typeof actual || expected === null || actual === null) {
    return { path, expected, actual };
  }
  if (Array.isArray(expected) || Array.isArray(actual)) {
    if (!Array.isArray(expected) || !Array.isArray(actual)) return { path, expected, actual };
    if (expected.length !== actual.length) {
      return { path: `${path}.length`, expected: expected.length, actual: actual.length };
    }
    for (let index = 0; index < expected.length; index += 1) {
      const mismatch = findMismatch(expected[index], actual[index], childPath(path, index));
      if (mismatch) return mismatch;
    }
    return null;
  }
  if (typeof expected === 'object') {
    const expectedKeys = Object.keys(expected);
    const actualKeys = Object.keys(actual);
    if (expectedKeys.length !== actualKeys.length) {
      const missing = expectedKeys.find((key) => !Object.hasOwn(actual, key));
      const extra = actualKeys.find((key) => !Object.hasOwn(expected, key));
      const key = missing ?? extra;
      return {
        path: childPath(path, key),
        expected: missing ? expected[key] : undefined,
        actual: extra ? actual[key] : undefined,
      };
    }
    for (const key of expectedKeys) {
      if (!Object.hasOwn(actual, key)) {
        return { path: childPath(path, key), expected: expected[key], actual: undefined };
      }
      const mismatch = findMismatch(expected[key], actual[key], childPath(path, key));
      if (mismatch) return mismatch;
    }
    return null;
  }
  return { path, expected, actual };
}

/**
 * Compare two parsed contract documents without depending on JSON formatting or key order.
 * @returns {true} when the values are semantically equal.
 * @throws {Error} with a JSONPath-like location when they differ.
 */
export function compareCaptureDocuments(expected, actual) {
  const mismatch = findMismatch(expected, actual);
  if (!mismatch) return true;
  throw new Error(
    `Contract mismatch at ${mismatch.path}: expected ${valueDescription(mismatch.expected)}, ` +
      `received ${valueDescription(mismatch.actual)}`,
  );
}

function validateDocument(value, label) {
  if (validate(value)) return value;
  throw new Error(`${label} failed capture schema validation: ${ajv.errorsText(validate.errors)}`);
}

async function runNative(nativeCli, fixture) {
  try {
    const result = await execFileAsync(nativeCli, [fixture, '--json'], { encoding: 'utf8' });
    return JSON.parse(result.stdout);
  } catch (error) {
    const detail = error && typeof error === 'object' && 'stderr' in error ? error.stderr : error;
    throw new Error(`Native parser failed: ${String(detail).trim()}`);
  }
}

function cString(module, pointer) {
  if (!pointer) return '';
  const heap = module.HEAPU8;
  let end = pointer;
  while (end < heap.length && heap[end] !== 0) end += 1;
  return new TextDecoder().decode(heap.subarray(pointer, end));
}

async function loadEmscriptenModule(modulePath) {
  const namespace = await import(pathToFileURL(modulePath).href);
  const factory = namespace.default ?? namespace;
  const wasmPath = modulePath.replace(/\.js$/, '.wasm');
  const raw =
    typeof factory === 'function' ? await factory({ locateFile: () => wasmPath }) : factory;
  if (!raw || typeof raw !== 'object' || !(raw.HEAPU8 instanceof Uint8Array)) {
    throw new Error('WebAssembly module did not initialize with HEAPU8');
  }
  const getExport = (name) => {
    const value = raw[name] ?? raw[`_${name}`];
    if (typeof value !== 'function') throw new Error(`WebAssembly export ${name} is missing`);
    return value.bind(raw);
  };
  return {
    get HEAPU8() {
      return raw.HEAPU8;
    },
    alloc: getExport('wirelens_alloc'),
    parseOwned: getExport('wirelens_parse_owned'),
    resultOk: getExport('wirelens_result_ok'),
    resultData: getExport('wirelens_result_data'),
    resultSize: getExport('wirelens_result_size'),
    resultErrorCode: getExport('wirelens_result_error_code'),
    release: getExport('wirelens_release'),
  };
}

async function runWasm(modulePath, fixture) {
  const module = await loadEmscriptenModule(modulePath);
  const bytes = await readFile(fixture);
  const pointer = module.alloc(bytes.byteLength);
  if (!pointer) throw new Error('WebAssembly allocation failed for fixture bytes');
  module.HEAPU8.set(bytes, pointer);
  let handle = 0;
  try {
    handle = module.parseOwned(pointer, bytes.byteLength);
    if (!handle) throw new Error('WebAssembly parser did not return a result handle');
    if (!module.resultOk(handle)) {
      const code = cString(module, module.resultErrorCode(handle));
      throw new Error(`WebAssembly parser failed${code ? `: ${code}` : ''}`);
    }
    const pointerToJson = module.resultData(handle);
    const size = module.resultSize(handle);
    if (!pointerToJson || !Number.isSafeInteger(size) || size < 1) {
      throw new Error('WebAssembly parser returned empty JSON');
    }
    return JSON.parse(
      new TextDecoder().decode(module.HEAPU8.subarray(pointerToJson, pointerToJson + size)),
    );
  } finally {
    if (handle) module.release(handle);
  }
}

async function main(argv) {
  if (argv.length < 2 || argv.length > 4) {
    throw new Error(
      'Usage: check-contract-parity.mjs <native-cli> <wasm-module> | <native-cli> <fixture> <wasm-module> [golden]',
    );
  }
  const resolveArg = (value) => (isAbsolute(value) ? value : resolve(repoRoot, value));
  const nativeCli = resolveArg(argv[0]);
  const fixture = argv.length >= 3 ? resolveArg(argv[1]) : null;
  const wasmModule = resolveArg(argv.length >= 3 ? argv[2] : argv[1]);
  const goldenPath = argv.length === 4 ? resolveArg(argv[3]) : null;
  const cases = fixture
    ? [[fixture, goldenPath]]
    : (await readdir(resolve(repoRoot, 'fixtures/generated')))
        .filter((name) => /\.(pcap|pcapng)$/u.test(name))
        .sort()
        .map((name) => [
          resolve(repoRoot, 'fixtures/generated', name),
          resolve(repoRoot, 'fixtures/expected', `${name}.capture.json`),
        ]);
  for (const [capturePath, expectedPath] of cases) {
    const native = validateDocument(
      await runNative(nativeCli, capturePath),
      `Native document (${capturePath})`,
    );
    const wasm = validateDocument(
      await runWasm(wasmModule, capturePath),
      `WebAssembly document (${capturePath})`,
    );
    compareCaptureDocuments(native, wasm);
    if (expectedPath) {
      const golden = validateDocument(
        JSON.parse(await readFile(expectedPath, 'utf8')),
        `Golden document (${expectedPath})`,
      );
      compareCaptureDocuments(native, golden);
    }
  }
  process.stdout.write(
    fixture || goldenPath
      ? 'Contract parity: native, WebAssembly, and golden documents match.\n'
      : 'Contract parity: native, WebAssembly, and all fixture goldens match.\n',
  );
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(scriptPath)) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
