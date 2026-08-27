import type { CaptureDocument, ParseError } from '@wirelens/schema';

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
