import type { CaptureDocument, ParseError } from './model';

export type CaptureState =
  | { status: 'empty' }
  | { status: 'loading'; fileName: string }
  | {
      status: 'ready';
      fileName: string;
      document: CaptureDocument;
      selectedPacketId: string | null;
      packetBytes: PacketBytesState;
    }
  | { status: 'error'; fileName: string | null; error: ParseError };

export type PacketBytesState =
  | { status: 'idle'; packetId: null; buffer: null; error: null }
  | { status: 'loading'; packetId: string; buffer: null; error: null }
  | { status: 'ready'; packetId: string; buffer: ArrayBuffer; error: null }
  | { status: 'error'; packetId: string; buffer: null; error: ParseError };

export interface CaptureParser {
  parse(file: File): Promise<CaptureDocument>;
  getPacketBytes?(packetIndex: number): Promise<ArrayBuffer>;
  dispose(): Promise<void> | void;
}

export interface CaptureStore {
  subscribe(run: (state: CaptureState) => void): () => void;
  getState(): CaptureState;
  selectFile(file: File): Promise<void>;
  selectPacket(packetId: string): void;
  dispose(): Promise<void>;
}

const parseErrorCodes = new Set<ParseError['code']>([
  'FILE_TOO_LARGE',
  'PACKET_LIMIT_EXCEEDED',
  'TRUNCATED_GLOBAL_HEADER',
  'UNSUPPORTED_MAGIC',
  'UNSUPPORTED_VERSION',
  'UNSUPPORTED_LINK_TYPE',
  'TRUNCATED_PACKET_HEADER',
  'INVALID_PACKET_LENGTH',
  'INVALID_TIMESTAMP',
  'TRUNCATED_PACKET_DATA',
  'TRUNCATED_PCAPNG_BLOCK',
  'TRUNCATED_PCAPNG_SECTION',
  'INVALID_PCAPNG_BYTE_ORDER',
  'INVALID_PCAPNG_BLOCK_LENGTH',
  'MISMATCHED_PCAPNG_BLOCK_LENGTH',
  'UNSUPPORTED_PCAPNG_VERSION',
  'INVALID_PCAPNG_SNAPLEN',
  'TRUNCATED_PCAPNG_OPTION',
  'INVALID_PCAPNG_OPTION_LENGTH',
  'MISSING_PCAPNG_OPTION_END',
  'TRUNCATED_PCAPNG_INTERFACE',
  'TRUNCATED_PCAPNG_PACKET',
  'INVALID_PCAPNG_INTERFACE',
  'INVALID_PCAPNG_PACKET_LENGTH',
  'PCAPNG_BLOCK_LIMIT_EXCEEDED',
  'PCAPNG_INTERFACE_LIMIT_EXCEEDED',
  'PCAPNG_SECTION_REQUIRED',
  'PCAPNG_PACKET_EXCEEDS_SNAPLEN',
  'PCAP_PACKET_EXCEEDS_SNAPLEN',
]);

function asParseError(reason: unknown): ParseError {
  if (reason && typeof reason === 'object') {
    const candidate = reason as Partial<ParseError>;
    if (
      parseErrorCodes.has(candidate.code as ParseError['code']) &&
      typeof candidate.message === 'string' &&
      (candidate.captureOffset === null || typeof candidate.captureOffset === 'number') &&
      (candidate.packetNumber === null || typeof candidate.packetNumber === 'number')
    ) {
      return candidate as ParseError;
    }
    if ((candidate as { code?: unknown }).code === 'FILE_TOO_LARGE') {
      return {
        code: 'FILE_TOO_LARGE',
        message: candidate.message ?? 'Capture exceeds the 64 MiB limit',
        captureOffset: null,
        packetNumber: null,
      };
    }
    if ((candidate as { code?: unknown }).code === 'UNSUPPORTED_FORMAT') {
      return {
        code: 'UNSUPPORTED_MAGIC',
        message: candidate.message ?? 'Only .pcap capture files are supported',
        captureOffset: null,
        packetNumber: null,
      };
    }
  }
  return {
    code: 'UNSUPPORTED_VERSION',
    message: reason instanceof Error ? reason.message : 'Capture parsing failed',
    captureOffset: null,
    packetNumber: null,
  };
}

function emptyPacketBytes(): PacketBytesState {
  return { status: 'idle', packetId: null, buffer: null, error: null };
}

export function createCaptureStore(parser: CaptureParser): CaptureStore {
  let state: CaptureState = { status: 'empty' };
  let operation = 0;
  let packetBytesOperation = 0;
  let disposed = false;
  const subscribers = new Set<(next: CaptureState) => void>();

  const publish = (next: CaptureState) => {
    state = next;
    for (const subscriber of subscribers) subscriber(state);
  };

  return {
    subscribe(run) {
      subscribers.add(run);
      run(state);
      return () => subscribers.delete(run);
    },

    getState() {
      return state;
    },

    async selectFile(file) {
      if (disposed) return;
      const currentOperation = ++operation;
      packetBytesOperation += 1;
      publish({ status: 'loading', fileName: file.name });
      try {
        const document = await parser.parse(file);
        if (disposed || currentOperation !== operation) return;
        const selectedPacketId = document.packets[0]?.id ?? null;
        publish({
          status: 'ready',
          fileName: file.name,
          document,
          selectedPacketId,
          packetBytes: emptyPacketBytes(),
        });
        if (selectedPacketId) loadPacketBytes(document, selectedPacketId, currentOperation);
      } catch (reason) {
        if (disposed || currentOperation !== operation) return;
        if (reason instanceof Error && reason.name === 'ParseCancelledError') return;
        publish({ status: 'error', fileName: file.name, error: asParseError(reason) });
      }
    },

    selectPacket(packetId) {
      if (state.status !== 'ready') return;
      if (!state.document.packets.some((packet) => packet.id === packetId)) return;
      packetBytesOperation += 1;
      publish({ ...state, selectedPacketId: packetId, packetBytes: emptyPacketBytes() });
      loadPacketBytes(state.document, packetId, operation);
    },

    async dispose() {
      if (disposed) return;
      disposed = true;
      operation += 1;
      packetBytesOperation += 1;
      if (state.status === 'ready') publish({ ...state, packetBytes: emptyPacketBytes() });
      await parser.dispose();
    },
  };

  function loadPacketBytes(
    document: CaptureDocument,
    packetId: string,
    currentOperation: number,
  ): void {
    if (!parser.getPacketBytes) return;
    const packetIndex = document.packets.findIndex((packet) => packet.id === packetId);
    if (packetIndex < 0) return;
    const currentPacketBytesOperation = ++packetBytesOperation;
    if (
      state.status !== 'ready' ||
      state.document !== document ||
      state.selectedPacketId !== packetId
    ) {
      return;
    }
    publish({
      ...state,
      packetBytes: { status: 'loading', packetId, buffer: null, error: null },
    });
    void Promise.resolve()
      .then(() => parser.getPacketBytes?.(packetIndex))
      .then(
        (buffer) => {
          if (
            !buffer ||
            disposed ||
            currentOperation !== operation ||
            currentPacketBytesOperation !== packetBytesOperation ||
            state.status !== 'ready' ||
            state.document !== document ||
            state.selectedPacketId !== packetId
          ) {
            return;
          }
          publish({
            ...state,
            packetBytes: { status: 'ready', packetId, buffer, error: null },
          });
        },
        (reason: unknown) => {
          if (
            disposed ||
            currentOperation !== operation ||
            currentPacketBytesOperation !== packetBytesOperation ||
            state.status !== 'ready' ||
            state.document !== document ||
            state.selectedPacketId !== packetId
          ) {
            return;
          }
          if (reason instanceof Error && reason.name === 'ParseCancelledError') return;
          publish({
            ...state,
            packetBytes: {
              status: 'error',
              packetId,
              buffer: null,
              error: asParseError(reason),
            },
          });
        },
      );
  }
}
