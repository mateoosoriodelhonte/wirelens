import { afterEach, describe, expect, it, vi } from 'vitest';
import { ParserClient, ParseCancelledError } from './parser-client';
import type { WorkerRequest, WorkerResponse } from './messages';
import { demoDocument } from '../demo-document';

class FakeWorker {
  readonly messages: Array<{ message: WorkerRequest; transfer: Transferable[] }> = [];
  terminated = false;
  onmessage: ((event: MessageEvent<WorkerResponse>) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;

  postMessage(message: WorkerRequest, transfer: Transferable[] = []) {
    this.messages.push({ message, transfer });
  }

  terminate() {
    this.terminated = true;
  }

  respond(response: WorkerResponse) {
    this.onmessage?.({ data: response } as MessageEvent<WorkerResponse>);
  }
}

const validFile = (name = 'capture.pcap', size = 3) =>
  Object.assign(new File([new Uint8Array(size)], name, { type: 'application/vnd.tcpdump.pcap' }), {
    arrayBuffer: async () => new Uint8Array(size).buffer,
  });

afterEach(() => vi.restoreAllMocks());

describe('ParserClient', () => {
  it('transfers the file buffer and resolves a validated document', async () => {
    const worker = new FakeWorker();
    const client = new ParserClient({ workerFactory: () => worker });

    const promise = client.parse(validFile());
    await vi.waitFor(() => expect(worker.messages).toHaveLength(1));
    const request = worker.messages[0];

    expect(request.message.type).toBe('parse');
    expect(request.transfer).toHaveLength(1);
    expect(request.transfer[0]).toBe(
      (request.message as Extract<WorkerRequest, { type: 'parse' }>).buffer,
    );

    worker.respond({
      type: 'parse-complete',
      requestId: (request.message as Extract<WorkerRequest, { type: 'parse' }>).requestId,
      document: demoDocument,
    });
    await expect(promise).resolves.toBe(demoDocument);
    await client.dispose();
  });

  it('rejects an unsupported extension before reading the file or creating a worker', async () => {
    const arrayBuffer = vi.fn();
    const file = Object.assign(validFile('capture.cap'), { arrayBuffer });
    const workerFactory = vi.fn(() => new FakeWorker());
    const client = new ParserClient({ workerFactory });

    await expect(client.parse(file)).rejects.toMatchObject({ code: 'UNSUPPORTED_FORMAT' });
    expect(arrayBuffer).not.toHaveBeenCalled();
    expect(workerFactory).not.toHaveBeenCalled();
  });

  it('rejects an oversized file before reading it or creating a worker', async () => {
    const arrayBuffer = vi.fn();
    const file = Object.assign(validFile('capture.pcap', 64 * 1024 * 1024 + 1), { arrayBuffer });
    const workerFactory = vi.fn(() => new FakeWorker());
    const client = new ParserClient({ workerFactory });

    await expect(client.parse(file)).rejects.toMatchObject({ code: 'FILE_TOO_LARGE' });
    expect(arrayBuffer).not.toHaveBeenCalled();
    expect(workerFactory).not.toHaveBeenCalled();
  });

  it('rejects a malformed worker response and removes its pending request', async () => {
    const worker = new FakeWorker();
    const client = new ParserClient({ workerFactory: () => worker });
    const promise = client.parse(validFile());
    await vi.waitFor(() => expect(worker.messages).toHaveLength(1));
    const requestId = (worker.messages[0].message as Extract<WorkerRequest, { type: 'parse' }>)
      .requestId;

    worker.respond({ type: 'parse-complete', requestId, document: {} as typeof demoDocument });
    await expect(promise).rejects.toThrow(/capture document/i);
    expect(client.pendingRequestCount).toBe(0);
  });

  it('rejects a typed worker failure and clears the pending request', async () => {
    const worker = new FakeWorker();
    const client = new ParserClient({ workerFactory: () => worker });
    const parse = client.parse(validFile());
    await vi.waitFor(() => expect(worker.messages).toHaveLength(1));
    const parseRequest = worker.messages[0].message as Extract<WorkerRequest, { type: 'parse' }>;
    worker.respond({
      type: 'failed',
      requestId: parseRequest.requestId,
      error: {
        code: 'TRUNCATED_GLOBAL_HEADER',
        message: 'short header',
        captureOffset: 0,
        packetNumber: null,
      },
    });
    await expect(parse).rejects.toMatchObject({ code: 'TRUNCATED_GLOBAL_HEADER' });
    expect(client.pendingRequestCount).toBe(0);
    await expect(client.getPacketBytes(0)).rejects.toThrow('No capture is open');
    await client.dispose();
  });

  it('cancels and terminates the previous worker when a new parse starts', async () => {
    const workers: FakeWorker[] = [];
    const client = new ParserClient({
      workerFactory: () => {
        const worker = new FakeWorker();
        workers.push(worker);
        return worker;
      },
    });

    const first = client.parse(validFile('first.pcap'));
    await vi.waitFor(() => expect(workers).toHaveLength(1));
    const second = client.parse(validFile('second.pcap'));
    await expect(first).rejects.toBeInstanceOf(ParseCancelledError);
    await vi.waitFor(() => expect(workers).toHaveLength(2));
    expect(workers[0].terminated).toBe(true);

    const request = workers[1].messages[0].message as Extract<WorkerRequest, { type: 'parse' }>;
    workers[1].respond({
      type: 'parse-complete',
      requestId: request.requestId,
      document: demoDocument,
    });
    await expect(second).resolves.toBe(demoDocument);
    await client.dispose();
  });

  it('uses monotonic request ids and safely disposes pending work', async () => {
    const workers: FakeWorker[] = [];
    const client = new ParserClient({
      workerFactory: () => {
        const worker = new FakeWorker();
        workers.push(worker);
        return worker;
      },
    });

    const first = client.parse(validFile());
    await vi.waitFor(() => expect(workers).toHaveLength(1));
    const firstRequest = workers[0].messages[0].message as Extract<
      WorkerRequest,
      { type: 'parse' }
    >;
    const firstId = firstRequest.requestId;
    workers[0].respond({
      type: 'parse-complete',
      requestId: firstRequest.requestId,
      document: demoDocument,
    });
    await first;

    const next = client.parse(validFile());
    await vi.waitFor(() => expect(workers).toHaveLength(2));
    const nextId = (workers[1].messages[0].message as Extract<WorkerRequest, { type: 'parse' }>)
      .requestId;
    expect(Number(nextId.replace('request-', ''))).toBeGreaterThan(
      Number(firstId.replace('request-', '')),
    );
    workers[1].respond({
      type: 'parse-complete',
      requestId: nextId,
      document: demoDocument,
    });
    await next;

    const pending = client.getPacketBytes(0);
    await vi.waitFor(() => expect(workers[1].messages).toHaveLength(2));
    await client.dispose();
    await expect(pending).rejects.toBeInstanceOf(ParseCancelledError);
    expect(workers[1].terminated).toBe(true);
    expect(client.pendingRequestCount).toBe(0);
    await expect(client.dispose()).resolves.toBeUndefined();
  });

  it('sends a safe release command and rejects later byte requests', async () => {
    const worker = new FakeWorker();
    const client = new ParserClient({ workerFactory: () => worker });
    const parse = client.parse(validFile());
    await vi.waitFor(() => expect(worker.messages).toHaveLength(1));
    const parseRequest = worker.messages[0].message as Extract<WorkerRequest, { type: 'parse' }>;
    worker.respond({
      type: 'parse-complete',
      requestId: parseRequest.requestId,
      document: demoDocument,
    });
    await parse;

    const packet = client.getPacketBytes(0);
    await vi.waitFor(() => expect(worker.messages).toHaveLength(2));
    const packetRequest = worker.messages[1].message as Extract<
      WorkerRequest,
      { type: 'packet-bytes' }
    >;
    const packetBuffer = new Uint8Array([1, 2, 3]).buffer;
    worker.respond({
      type: 'packet-bytes',
      requestId: packetRequest.requestId,
      packetIndex: 0,
      buffer: packetBuffer,
    });
    await expect(packet).resolves.toBe(packetBuffer);

    client.release();
    expect(worker.messages).toHaveLength(3);
    expect(worker.messages[2].message.type).toBe('release');
    await expect(client.getPacketBytes(0)).rejects.toThrow('No capture is open');
    client.release();
    await client.dispose();
  });
});
