import { validateCaptureDocument } from '@wirelens/schema';
import type { ParseError } from '@wirelens/schema';
import { isWorkerRequest } from './messages';
import type { WorkerRequest, WorkerResponse } from './messages';
import { loadWasmModule } from '../wasm/module';
import type { WasmModule } from '../wasm/module';

interface WorkerScope {
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null;
  postMessage(message: WorkerResponse, transfer?: Transferable[]): void;
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

const textDecoder = new TextDecoder();

function readCString(module: WasmModule, pointer: number): string {
  if (!pointer) return '';
  const heap = module.HEAPU8;
  let end = pointer;
  while (end < heap.length && heap[end] !== 0) end += 1;
  return textDecoder.decode(heap.subarray(pointer, end));
}

function parseFailure(module: WasmModule, handle: number): ParseError {
  const candidate = readCString(module, module.wirelens_result_error_code(handle));
  const code = parseErrorCodes.has(candidate as ParseError['code'])
    ? (candidate as ParseError['code'])
    : 'UNSUPPORTED_VERSION';
  const rawOffset = module.wirelens_result_error_offset(handle);
  const offset =
    typeof rawOffset === 'bigint'
      ? rawOffset === 0xffffffffffffffffn || rawOffset === -1n
        ? null
        : rawOffset
      : rawOffset === -1
        ? null
        : rawOffset;
  return {
    code,
    message: candidate ? `Capture parse failed: ${candidate}` : 'Capture parse failed',
    captureOffset:
      offset === null ||
      (typeof offset === 'bigint'
        ? offset > BigInt(Number.MAX_SAFE_INTEGER)
        : offset === Number.MAX_SAFE_INTEGER)
        ? null
        : Number(offset),
    packetNumber: null,
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
