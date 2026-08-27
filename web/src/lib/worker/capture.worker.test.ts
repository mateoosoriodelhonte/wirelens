// @vitest-environment node
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { WorkerRequest, WorkerResponse } from './messages';
import { createCaptureWorker } from './capture.worker';
import { loadWasmModule } from '../wasm/module';
import type { WasmModule } from '../wasm/module';

class WorkerHarness {
  readonly responses: Array<{ response: WorkerResponse; transfer: Transferable[] }> = [];
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null = null;

  postMessage(response: WorkerResponse, transfer: Transferable[] = []) {
    this.responses.push({ response, transfer });
  }

  send(request: WorkerRequest) {
    this.onmessage?.({ data: request } as MessageEvent<WorkerRequest>);
  }
}

const fakeModule = (overrides: Partial<WasmModule> = {}): WasmModule => {
  const heap = new Uint8Array(1024);
  return {
    HEAPU8: heap,
    wirelens_alloc: () => 8,
    wirelens_parse_owned: () => 1,
    wirelens_result_ok: () => 0,
    wirelens_result_data: () => 0,
    wirelens_result_size: () => 0,
    wirelens_result_error_code: () => 0,
    wirelens_result_error_offset: () => Number.MAX_SAFE_INTEGER,
    wirelens_packet_data: () => 0,
    wirelens_packet_size: () => 0,
    wirelens_release: () => undefined,
    ...overrides,
  };
};

const waitForResponse = async (harness: WorkerHarness, requestId: string) => {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const result = harness.responses.find(
      ({ response }) => 'requestId' in response && response.requestId === requestId,
    );
    if (result) return result;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 10));
  }
  throw new Error(`Timed out waiting for worker response ${requestId}`);
};

describe('capture worker with the generated Emscripten module', () => {
  it('parses the handshake fixture, transfers packet bytes, and releases the result', async () => {
    const modulePath = resolve(process.cwd(), 'static/wasm/wirelens.js');
    const wasmPath = resolve(process.cwd(), 'static/wasm/wirelens.wasm');
    expect(existsSync(modulePath) && existsSync(wasmPath)).toBe(true);
    const fixture = readFileSync(
      resolve(process.cwd(), '../fixtures/generated/tcp-handshake.pcap'),
    );
    const harness = new WorkerHarness();
    const module = await loadWasmModule({
      moduleUrl: pathToFileURL(modulePath).href,
      wasmUrl: pathToFileURL(wasmPath).href,
    });
    createCaptureWorker(harness, async () => module);

    harness.send({
      type: 'parse',
      requestId: 'request-parse',
      fileName: 'tcp-handshake.pcap',
      buffer: fixture.buffer.slice(fixture.byteOffset, fixture.byteOffset + fixture.byteLength),
    });
    const complete = await waitForResponse(harness, 'request-parse');
    expect(complete.response.type).toBe('parse-complete');
    if (complete.response.type !== 'parse-complete') return;
    expect(complete.response.document.capture.packetCount).toBe(3);

    harness.send({ type: 'packet-bytes', requestId: 'request-bytes', packetIndex: 0 });
    const packet = await waitForResponse(harness, 'request-bytes');
    expect(packet.response.type).toBe('packet-bytes');
    expect(packet.transfer).toHaveLength(1);
    if (packet.response.type !== 'packet-bytes') return;
    expect(new Uint8Array(packet.response.buffer).byteLength).toBe(54);

    harness.send({ type: 'packet-bytes', requestId: 'request-bad-index', packetIndex: 99 });
    const badIndex = await waitForResponse(harness, 'request-bad-index');
    expect(badIndex.response).toMatchObject({
      type: 'failed',
      error: { code: 'TRUNCATED_PACKET_DATA' },
    });

    harness.send({ type: 'release', requestId: 'request-release' });
    harness.send({ type: 'packet-bytes', requestId: 'request-after-release', packetIndex: 0 });
    const failed = await waitForResponse(harness, 'request-after-release');
    expect(failed.response).toMatchObject({
      type: 'failed',
      requestId: 'request-after-release',
      error: { code: 'TRUNCATED_PACKET_DATA' },
    });
  });

  it('releases a typed parse failure handle and does not allocate for empty input', async () => {
    const harness = new WorkerHarness();
    const releases: number[] = [];
    let allocations = 0;
    const module = fakeModule({
      wirelens_alloc: () => {
        allocations += 1;
        return 8;
      },
      wirelens_release: (handle) => releases.push(handle),
    });
    createCaptureWorker(harness, async () => module);

    harness.send({
      type: 'parse',
      requestId: 'request-empty',
      fileName: 'empty.pcap',
      buffer: new ArrayBuffer(0),
    });
    const empty = await waitForResponse(harness, 'request-empty');
    expect(empty.response).toMatchObject({
      type: 'failed',
      error: { code: 'TRUNCATED_GLOBAL_HEADER' },
    });
    expect(allocations).toBe(0);

    harness.send({
      type: 'parse',
      requestId: 'request-failed',
      fileName: 'broken.pcap',
      buffer: new ArrayBuffer(4),
    });
    const failed = await waitForResponse(harness, 'request-failed');
    expect(failed.response).toMatchObject({
      type: 'failed',
      error: { code: 'UNSUPPORTED_VERSION' },
    });
    expect(releases).toEqual([1]);
  });

  it('reports a packet request when no capture is open', async () => {
    const harness = new WorkerHarness();
    const module = fakeModule({
      wirelens_result_ok: () => 1,
      wirelens_result_data: () => 8,
      wirelens_result_size: () => 2,
    });
    module.HEAPU8.set(new TextEncoder().encode('{"schema":"bad"}'), 8);
    createCaptureWorker(harness, async () => module);
    harness.send({
      type: 'parse',
      requestId: 'request-parse',
      fileName: 'capture.pcap',
      buffer: new ArrayBuffer(1),
    });
    await waitForResponse(harness, 'request-parse');
    harness.send({ type: 'packet-bytes', requestId: 'request-bad-index', packetIndex: 99 });
    const failed = await waitForResponse(harness, 'request-bad-index');
    expect(failed.response).toMatchObject({
      type: 'failed',
      error: { code: 'TRUNCATED_PACKET_DATA' },
    });
  });
});
