import { describe, expect, it, vi } from 'vitest';
import { demoDocument } from './demo-document';
import { createCaptureStore, type CaptureParser } from './capture-store';
import { ParseCancelledError } from './worker/parser-client';
import type { CaptureDocument } from './model';

const file = (name = 'capture.pcap') => new File(['capture'], name);

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function parser(overrides: Partial<CaptureParser> = {}): CaptureParser {
  return {
    parse: vi.fn(async () => demoDocument),
    dispose: vi.fn(async () => undefined),
    ...overrides,
  };
}

describe('capture store', () => {
  it('transitions from empty to loading to ready and selects the first packet', async () => {
    const client = parser();
    const store = createCaptureStore(client);
    const states = [] as ReturnType<typeof store.getState>[];
    const unsubscribe = store.subscribe((state) => states.push(state));

    const pending = store.selectFile(file('handshake.pcap'));
    expect(store.getState()).toEqual({ status: 'loading', fileName: 'handshake.pcap' });
    await pending;
    expect(store.getState()).toEqual({
      status: 'ready',
      fileName: 'handshake.pcap',
      document: demoDocument,
      selectedPacketId: 'packet-1',
      packetBytes: { status: 'idle', packetId: null, buffer: null, error: null },
    });
    expect(states.map((state) => state.status)).toEqual(['empty', 'loading', 'ready']);
    unsubscribe();
  });

  it('turns a typed parser failure into an error state', async () => {
    const error = {
      code: 'TRUNCATED_GLOBAL_HEADER' as const,
      message: 'Capture header is truncated',
      captureOffset: 0,
      packetNumber: null,
    };
    const client = parser({ parse: vi.fn(async () => Promise.reject({ ...error })) });
    const store = createCaptureStore(client);

    await store.selectFile(file('broken.pcap'));

    expect(store.getState()).toEqual({ status: 'error', fileName: 'broken.pcap', error });
  });

  it('ignores a stale result when a second file is selected', async () => {
    const first = deferred<CaptureDocument>();
    const second = deferred<CaptureDocument>();
    const parse = vi.fn((selected: File) =>
      selected.name === 'first.pcap' ? first.promise : second.promise,
    );
    const client = parser({ parse });
    const store = createCaptureStore(client);

    const firstLoad = store.selectFile(file('first.pcap'));
    const secondLoad = store.selectFile(file('second.pcap'));
    second.resolve(demoDocument);
    await secondLoad;
    first.resolve({ ...demoDocument, capture: { ...demoDocument.capture, packetCount: 99 } });
    await firstLoad;

    expect(store.getState()).toMatchObject({ status: 'ready', fileName: 'second.pcap' });
    expect(store.getState()).not.toMatchObject({ document: { capture: { packetCount: 99 } } });
  });

  it('does not replace the current ready state for cancellation from stale work', async () => {
    const first = deferred<CaptureDocument>();
    const parse = vi.fn(() => first.promise);
    const client = parser({ parse });
    const store = createCaptureStore(client);
    const firstLoad = store.selectFile(file('first.pcap'));
    const secondLoad = store.selectFile(file('second.pcap'));
    first.reject(new ParseCancelledError());
    await firstLoad;
    expect(store.getState()).toEqual({ status: 'loading', fileName: 'second.pcap' });
    secondLoad.catch(() => undefined);
  });

  it('selects a packet only when it exists in the ready document', async () => {
    const store = createCaptureStore(parser());
    await store.selectFile(file());

    store.selectPacket('packet-2');
    expect(store.getState()).toMatchObject({ status: 'ready', selectedPacketId: 'packet-2' });
    store.selectPacket('missing');
    expect(store.getState()).toMatchObject({ status: 'ready', selectedPacketId: 'packet-2' });
  });

  it('loads exactly one selected packet buffer and clears it on replacement', async () => {
    const firstBytes = deferred<ArrayBuffer>();
    const secondBytes = deferred<ArrayBuffer>();
    const getPacketBytes = vi.fn((packetIndex: number) =>
      packetIndex === 0 ? firstBytes.promise : secondBytes.promise,
    );
    const store = createCaptureStore(parser({ getPacketBytes }));

    await store.selectFile(file());
    expect(store.getState()).toMatchObject({
      status: 'ready',
      selectedPacketId: 'packet-1',
      packetBytes: { status: 'loading', packetId: 'packet-1', buffer: null },
    });

    store.selectPacket('packet-2');
    expect(store.getState()).toMatchObject({
      status: 'ready',
      selectedPacketId: 'packet-2',
      packetBytes: { status: 'loading', packetId: 'packet-2', buffer: null },
    });

    const secondBuffer = new Uint8Array([0x22]).buffer;
    secondBytes.resolve(secondBuffer);
    await vi.waitFor(() =>
      expect(store.getState()).toMatchObject({
        packetBytes: { status: 'ready', packetId: 'packet-2', buffer: secondBuffer },
      }),
    );
    firstBytes.resolve(new Uint8Array([0x11]).buffer);

    expect(getPacketBytes).toHaveBeenNthCalledWith(1, 0);
    expect(getPacketBytes).toHaveBeenNthCalledWith(2, 1);
    expect(store.getState()).toMatchObject({
      selectedPacketId: 'packet-2',
      packetBytes: { status: 'ready', packetId: 'packet-2', buffer: secondBuffer },
    });
  });

  it('reports a selected packet byte fetch failure without retaining bytes', async () => {
    const error = {
      code: 'TRUNCATED_PACKET_DATA' as const,
      message: 'Packet bytes are not available',
      captureOffset: null,
      packetNumber: 1,
    };
    const getPacketBytes = vi.fn(async () => Promise.reject(error));
    const store = createCaptureStore(parser({ getPacketBytes }));

    await store.selectFile(file());
    await vi.waitFor(() =>
      expect(store.getState()).toMatchObject({
        packetBytes: { status: 'error', packetId: 'packet-1', buffer: null, error },
      }),
    );

    expect(store.getState()).toMatchObject({
      status: 'ready',
      packetBytes: { status: 'error', packetId: 'packet-1', buffer: null, error },
    });
  });

  it('clears the selected packet buffer as soon as a new capture starts', async () => {
    const firstBuffer = new Uint8Array([0x01]).buffer;
    const secondParse = deferred<CaptureDocument>();
    const parse = vi.fn((selected: File) =>
      selected.name === 'first.pcap' ? Promise.resolve(demoDocument) : secondParse.promise,
    );
    const getPacketBytes = vi.fn(async () => firstBuffer);
    const store = createCaptureStore(parser({ parse, getPacketBytes }));

    await store.selectFile(file('first.pcap'));
    await vi.waitFor(() =>
      expect(store.getState()).toMatchObject({
        packetBytes: { status: 'ready', buffer: firstBuffer },
      }),
    );

    const nextCapture = store.selectFile(file('second.pcap'));
    expect(store.getState()).toEqual({ status: 'loading', fileName: 'second.pcap' });
    secondParse.resolve(demoDocument);
    await nextCapture;
  });

  it('disposes the parser and ignores work that finishes after disposal', async () => {
    const pending = deferred<CaptureDocument>();
    const client = parser({ parse: vi.fn(() => pending.promise) });
    const store = createCaptureStore(client);
    const load = store.selectFile(file());
    await store.dispose();
    pending.resolve(demoDocument);
    await load;

    expect(client.dispose).toHaveBeenCalledTimes(1);
    expect(store.getState()).toEqual({ status: 'loading', fileName: 'capture.pcap' });
  });
});
