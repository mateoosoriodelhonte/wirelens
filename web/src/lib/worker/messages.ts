import type { CaptureDocument, ParseError } from '@wirelens/schema';

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

export type WorkerRequest =
  | { type: 'parse'; requestId: string; fileName: string; buffer: ArrayBuffer }
  | { type: 'packet-bytes'; requestId: string; packetIndex: number }
  | { type: 'release'; requestId: string };

export type WorkerResponse =
  | { type: 'ready' }
  | { type: 'parse-complete'; requestId: string; document: CaptureDocument }
  | { type: 'packet-bytes'; requestId: string; packetIndex: number; buffer: ArrayBuffer }
  | { type: 'failed'; requestId: string; error: ParseError };

export function isParseError(value: unknown): value is ParseError {
  if (!value || typeof value !== 'object') return false;
  const error = value as Partial<ParseError>;
  return (
    parseErrorCodes.has(error.code as ParseError['code']) &&
    typeof error.message === 'string' &&
    (error.captureOffset === null || typeof error.captureOffset === 'number') &&
    (error.packetNumber === null || typeof error.packetNumber === 'number')
  );
}

export function isWorkerResponse(value: unknown): value is WorkerResponse {
  if (
    !value ||
    typeof value !== 'object' ||
    typeof (value as { type?: unknown }).type !== 'string'
  ) {
    return false;
  }
  const response = value as Partial<WorkerResponse>;
  if (response.type === 'ready') return true;
  const requestId = (response as { requestId?: unknown }).requestId;
  if (typeof requestId !== 'string') return false;
  if (response.type === 'failed') return isParseError((response as { error?: unknown }).error);
  if (response.type === 'packet-bytes') {
    return typeof response.packetIndex === 'number' && response.buffer instanceof ArrayBuffer;
  }
  return (
    response.type === 'parse-complete' &&
    !!response.document &&
    typeof response.document === 'object'
  );
}

export function isWorkerRequest(value: unknown): value is WorkerRequest {
  if (!value || typeof value !== 'object') return false;
  const request = value as Partial<WorkerRequest>;
  if (typeof request.type !== 'string' || typeof request.requestId !== 'string') return false;
  if (request.type === 'parse') {
    return typeof request.fileName === 'string' && request.buffer instanceof ArrayBuffer;
  }
  if (request.type === 'packet-bytes') {
    return (
      typeof request.packetIndex === 'number' &&
      Number.isInteger(request.packetIndex) &&
      request.packetIndex >= 0
    );
  }
  return request.type === 'release';
}
