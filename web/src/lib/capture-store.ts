import type { CaptureDocument, ParseError } from './model';

export type CaptureState =
  | { status: 'empty' }
  | { status: 'loading'; fileName: string }
  | {
      status: 'ready';
      fileName: string;
      document: CaptureDocument;
      selectedPacketId: string | null;
    }
  | { status: 'error'; fileName: string | null; error: ParseError };

export interface CaptureParser {
  parse(file: File): Promise<CaptureDocument>;
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
  'TRUNCATED_GLOBAL_HEADER',
  'UNSUPPORTED_MAGIC',
  'UNSUPPORTED_VERSION',
  'UNSUPPORTED_LINK_TYPE',
  'TRUNCATED_PACKET_HEADER',
  'INVALID_PACKET_LENGTH',
  'TRUNCATED_PACKET_DATA',
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

export function createCaptureStore(parser: CaptureParser): CaptureStore {
  let state: CaptureState = { status: 'empty' };
  let operation = 0;
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
      publish({ status: 'loading', fileName: file.name });
      try {
        const document = await parser.parse(file);
        if (disposed || currentOperation !== operation) return;
        publish({
          status: 'ready',
          fileName: file.name,
          document,
          selectedPacketId: document.packets[0]?.id ?? null,
        });
      } catch (reason) {
        if (disposed || currentOperation !== operation) return;
        if (reason instanceof Error && reason.name === 'ParseCancelledError') return;
        publish({ status: 'error', fileName: file.name, error: asParseError(reason) });
      }
    },

    selectPacket(packetId) {
      if (state.status !== 'ready') return;
      if (!state.document.packets.some((packet) => packet.id === packetId)) return;
      publish({ ...state, selectedPacketId: packetId });
    },

    async dispose() {
      if (disposed) return;
      disposed = true;
      operation += 1;
      await parser.dispose();
    },
  };
}
