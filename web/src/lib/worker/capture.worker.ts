import { validateCaptureDocument } from '@wirelens/schema';
import type { ParseError } from '@wirelens/schema';
import { isWorkerRequest } from './messages';
import type { WorkerRequest, WorkerResponse } from './messages';
import { MAX_CAPTURE_BYTES } from './limits';
import { loadWasmModule } from '../wasm/module';
import type { WasmModule } from '../wasm/module';

interface WorkerScope {
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null;
  postMessage(message: WorkerResponse, transfer?: Transferable[]): void;
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

const parseErrorMessages: Partial<Record<ParseError['code'], string>> = {
  PACKET_LIMIT_EXCEEDED: 'Capture exceeds the 65,536 packet limit',
};

const textDecoder = new TextDecoder();

function readCString(module: WasmModule, pointer: number): string {
  if (!pointer) return '';
  const heap = module.HEAPU8;
  let end = pointer;
  while (end < heap.length && heap[end] !== 0) end += 1;
  return textDecoder.decode(heap.subarray(pointer, end));
}

function optionalAbiNumber(raw: number | bigint): number | null {
  if (typeof raw === 'bigint') {
    if (raw === 0xffffffffffffffffn || raw === -1n || raw < 0n) return null;
    return raw > BigInt(Number.MAX_SAFE_INTEGER) ? null : Number(raw);
  }
  if (raw === -1 || raw === Number.MAX_SAFE_INTEGER) return null;
  return Number.isSafeInteger(raw) && raw >= 0 ? raw : null;
}

function parseFailure(module: WasmModule, handle: number): ParseError {
  const candidate = readCString(module, module.wirelens_result_error_code(handle));
  const code = parseErrorCodes.has(candidate as ParseError['code'])
    ? (candidate as ParseError['code'])
    : 'UNSUPPORTED_VERSION';
  return {
    code,
    message:
      parseErrorMessages[code] ??
      (candidate ? `Capture parse failed: ${candidate}` : 'Capture parse failed'),
    captureOffset: optionalAbiNumber(module.wirelens_result_error_offset(handle)),
    packetNumber: optionalAbiNumber(module.wirelens_result_error_packet_number(handle)),
  };
}

function failed(requestId: string, error: ParseError): WorkerResponse {
  return { type: 'failed', requestId, error };
}

export function createCaptureWorker(
  scope: WorkerScope,
  moduleLoader: () => Promise<WasmModule> = () => loadWasmModule(),
): void {
  let activeHandle = 0;
  const modulePromise = moduleLoader();

  const releaseActive = (module: WasmModule) => {
    if (!activeHandle) return;
    module.wirelens_release(activeHandle);
    activeHandle = 0;
  };

  const handleRequest = async (request: WorkerRequest) => {
    const module = await modulePromise;
    if (request.type === 'release') {
      releaseActive(module);
      return;
    }
    if (request.type === 'parse') {
      releaseActive(module);
      if (request.buffer.byteLength > MAX_CAPTURE_BYTES) {
        scope.postMessage(
          failed(request.requestId, {
            code: 'FILE_TOO_LARGE',
            message: 'Capture exceeds the 64 MiB limit',
            captureOffset: null,
            packetNumber: null,
          }),
        );
        return;
      }
      if (request.buffer.byteLength === 0) {
        scope.postMessage(
          failed(request.requestId, {
            code: 'TRUNCATED_GLOBAL_HEADER',
            message: 'Capture is empty; the 24-byte global header is truncated',
            captureOffset: 0,
            packetNumber: null,
          }),
        );
        return;
      }

      let handle = 0;
      try {
        const bytes = new Uint8Array(request.buffer);
        const pointer = module.wirelens_alloc(bytes.byteLength);
        if (!pointer) {
          scope.postMessage(
            failed(request.requestId, {
              code: 'FILE_TOO_LARGE',
              message: 'WebAssembly memory allocation failed',
              captureOffset: null,
              packetNumber: null,
            }),
          );
          return;
        }
        module.HEAPU8.set(bytes, pointer);
        handle = module.wirelens_parse_owned(pointer, bytes.byteLength);
        if (!handle) {
          scope.postMessage(
            failed(request.requestId, {
              code: 'UNSUPPORTED_VERSION',
              message: 'WebAssembly parser did not return a result',
              captureOffset: null,
              packetNumber: null,
            }),
          );
          return;
        }
        if (!module.wirelens_result_ok(handle)) {
          scope.postMessage(failed(request.requestId, parseFailure(module, handle)));
          return;
        }
        const jsonPointer = module.wirelens_result_data(handle);
        const jsonSize = module.wirelens_result_size(handle);
        const document = validateCaptureDocument(
          JSON.parse(
            textDecoder.decode(module.HEAPU8.subarray(jsonPointer, jsonPointer + jsonSize)),
          ),
        );
        scope.postMessage({ type: 'parse-complete', requestId: request.requestId, document });
        activeHandle = handle;
        handle = 0;
      } catch (error) {
        const message = error instanceof Error ? error.message : 'WebAssembly parser failed';
        scope.postMessage(
          failed(request.requestId, {
            code: 'UNSUPPORTED_VERSION',
            message,
            captureOffset: null,
            packetNumber: null,
          }),
        );
      } finally {
        if (handle) module.wirelens_release(handle);
      }
      return;
    }

    if (!activeHandle) {
      scope.postMessage(
        failed(request.requestId, {
          code: 'TRUNCATED_PACKET_DATA',
          message: 'No capture is open',
          captureOffset: null,
          packetNumber: request.packetIndex + 1,
        }),
      );
      return;
    }
    const pointer = module.wirelens_packet_data(activeHandle, request.packetIndex);
    const size = module.wirelens_packet_size(activeHandle, request.packetIndex);
    if (!pointer) {
      scope.postMessage(
        failed(request.requestId, {
          code: 'TRUNCATED_PACKET_DATA',
          message: `Packet ${request.packetIndex + 1} bytes are not available`,
          captureOffset: null,
          packetNumber: request.packetIndex + 1,
        }),
      );
      return;
    }
    const buffer = module.HEAPU8.slice(pointer, pointer + size).buffer;
    scope.postMessage(
      {
        type: 'packet-bytes',
        requestId: request.requestId,
        packetIndex: request.packetIndex,
        buffer,
      },
      [buffer],
    );
  };

  scope.onmessage = (event) => {
    if (!isWorkerRequest(event.data)) return;
    void handleRequest(event.data).catch((error: unknown) => {
      const message = error instanceof Error ? error.message : 'Capture worker failed';
      scope.postMessage(
        failed(event.data.requestId, {
          code: 'UNSUPPORTED_VERSION',
          message,
          captureOffset: null,
          packetNumber: null,
        }),
      );
    });
  };

  void modulePromise.then(
    () => scope.postMessage({ type: 'ready' }),
    () => {
      // The request that triggered the load receives the typed failure below.
    },
  );
}

if (typeof document === 'undefined' && typeof self !== 'undefined') {
  createCaptureWorker(self as unknown as WorkerScope);
}
