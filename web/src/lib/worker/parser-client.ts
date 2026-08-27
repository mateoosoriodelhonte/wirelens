import { validateCaptureDocument } from '@wirelens/schema';
import type { CaptureDocument, ParseError } from '@wirelens/schema';
import { isWorkerResponse } from './messages';
import type { WorkerRequest, WorkerResponse } from './messages';

export const MAX_CAPTURE_BYTES = 64 * 1024 * 1024;

export class ParseCancelledError extends Error {
  constructor(message = 'Capture parsing was cancelled') {
    super(message);
    this.name = 'ParseCancelledError';
  }
}

export class ParserInputError extends Error {
  readonly code: 'UNSUPPORTED_FORMAT' | 'FILE_TOO_LARGE';

  constructor(code: ParserInputError['code'], message: string) {
    super(message);
    this.name = 'ParserInputError';
    this.code = code;
  }
}

export class ParseFailureError extends Error implements ParseError {
  readonly code: ParseError['code'];
  readonly captureOffset: number | null;
  readonly packetNumber: number | null;
  readonly parseError: ParseError;

  constructor(error: ParseError) {
    super(error.message);
    this.name = 'ParseFailureError';
    this.code = error.code;
    this.captureOffset = error.captureOffset;
    this.packetNumber = error.packetNumber;
    this.parseError = error;
  }
}

interface ParserWorker {
  onmessage: ((event: MessageEvent<WorkerResponse>) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
  postMessage(message: WorkerRequest, transfer?: Transferable[]): void;
  terminate(): void;
}

export type WorkerFactory = (url?: string, options?: { type: 'module' }) => ParserWorker;

export interface ParserClientOptions {
  workerFactory?: WorkerFactory;
  workerUrl?: string;
}

interface PendingRequest<T> {
  kind: 'parse' | 'packet-bytes';
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
}

interface ParseOperation {
  cancelled: boolean;
  reject: (reason?: unknown) => void;
}

const defaultWorkerFactory: WorkerFactory = () =>
  new Worker(new URL('./capture.worker.ts', import.meta.url), {
    type: 'module',
  }) as unknown as ParserWorker;

function inputError(file: Pick<File, 'name' | 'size'>): ParserInputError | null {
  if (!file.name.toLowerCase().endsWith('.pcap')) {
    return new ParserInputError('UNSUPPORTED_FORMAT', 'Only .pcap capture files are supported');
  }
  if (file.size > MAX_CAPTURE_BYTES) {
    return new ParserInputError('FILE_TOO_LARGE', 'Capture exceeds the 64 MiB limit');
  }
  return null;
}

export class ParserClient {
  private readonly workerFactory: WorkerFactory;
  private readonly workerUrl: string;
  private worker: ParserWorker | null = null;
  private hasCapture = false;
  private nextRequestNumber = 1;
  private readonly pending = new Map<string, PendingRequest<unknown>>();
  private activeParse: ParseOperation | null = null;

  constructor(options: ParserClientOptions = {}) {
    this.workerFactory = options.workerFactory ?? defaultWorkerFactory;
    this.workerUrl = options.workerUrl ?? '';
  }

  get pendingRequestCount(): number {
    return this.pending.size;
  }

  parse(file: File): Promise<CaptureDocument> {
    const validationError = inputError(file);
    if (validationError) return Promise.reject(validationError);

    this.cancelCurrent(new ParseCancelledError());
    this.hasCapture = false;

    let operation!: ParseOperation;
    const promise = new Promise<CaptureDocument>((resolve, reject) => {
      operation = { cancelled: false, reject };
      void this.startParse(file, operation, resolve, reject);
    });
    this.activeParse = operation;
    return promise;
  }

  getPacketBytes(packetIndex: number): Promise<ArrayBuffer> {
    if (!Number.isInteger(packetIndex) || packetIndex < 0) {
      return Promise.reject(new RangeError('packetIndex must be a non-negative integer'));
    }
    if (!this.worker || !this.hasCapture) return Promise.reject(new Error('No capture is open'));
    const requestId = this.newRequestId();
    return new Promise<ArrayBuffer>((resolve, reject) => {
      this.pending.set(requestId, {
        kind: 'packet-bytes',
        resolve: (value) => resolve(value as ArrayBuffer),
        reject,
      });
      try {
        this.worker?.postMessage({ type: 'packet-bytes', requestId, packetIndex });
      } catch (error) {
        this.rejectPending(requestId, error);
      }
    });
  }

  release(): void {
    this.hasCapture = false;
    if (this.activeParse) {
      this.activeParse.cancelled = true;
      this.activeParse.reject(new ParseCancelledError());
      this.activeParse = null;
    }
    for (const [requestId, request] of this.pending) {
      this.pending.delete(requestId);
      request.reject(new ParseCancelledError());
    }
    if (!this.worker) return;
    const requestId = this.newRequestId();
    try {
      this.worker.postMessage({ type: 'release', requestId });
    } catch {
      // Release is deliberately best effort. The worker will be reclaimed on dispose.
    }
  }

  async dispose(): Promise<void> {
    this.cancelCurrent(new ParseCancelledError());
    this.release();
    this.terminateWorker();
  }

  private async startParse(
    file: File,
    operation: ParseOperation,
    resolve: (document: CaptureDocument) => void,
    reject: (reason?: unknown) => void,
  ): Promise<void> {
    try {
      const buffer = await file.arrayBuffer();
      if (operation.cancelled) return;

      const worker = this.workerFactory(this.workerUrl, { type: 'module' });
      this.worker = worker;
      worker.onmessage = (event) => this.handleResponse(event.data);
      worker.onerror = (event) => this.handleWorkerError(event);

      const requestId = this.newRequestId();
      this.pending.set(requestId, {
        kind: 'parse',
        resolve: (value) => resolve(value as CaptureDocument),
        reject,
      });
      const request: Extract<WorkerRequest, { type: 'parse' }> = {
        type: 'parse',
        requestId,
        fileName: file.name,
        buffer,
      };
      try {
        worker.postMessage(request, [buffer]);
      } catch (error) {
        this.rejectPending(requestId, error);
        this.terminateWorker();
      }
    } catch (error) {
      if (!operation.cancelled) {
        reject(error);
        if (this.activeParse === operation) this.activeParse = null;
      }
    }
  }

  private handleResponse(response: unknown): void {
    if (!isWorkerResponse(response)) {
      const requestId = this.requestIdOf(response);
      if (requestId && this.pending.has(requestId)) {
        this.rejectPending(requestId, new Error('Malformed response from capture worker'));
      } else {
        this.rejectAll(new Error('Malformed response from capture worker'));
      }
      return;
    }
    if (response.type === 'ready') return;

    const request = this.pending.get(response.requestId);
    if (!request) return;
    if (response.type === 'failed') {
      this.rejectPending(response.requestId, new ParseFailureError(response.error));
      return;
    }
    if (response.type === 'packet-bytes') {
      this.resolvePending(response.requestId, response.buffer);
      return;
    }
    try {
      this.resolvePending(response.requestId, validateCaptureDocument(response.document));
      this.hasCapture = true;
    } catch (error) {
      this.rejectPending(response.requestId, error);
    }
    if (this.activeParse && !this.pending.has(response.requestId)) this.activeParse = null;
  }

  private handleWorkerError(event: ErrorEvent): void {
    if (this.activeParse) {
      this.activeParse.cancelled = true;
      this.activeParse = null;
    }
    this.rejectAll(event.error ?? new Error(event.message || 'Capture worker failed'));
    this.terminateWorker();
  }

  private cancelCurrent(error: ParseCancelledError): void {
    const operation = this.activeParse;
    if (operation) {
      operation.cancelled = true;
      operation.reject(error);
      this.activeParse = null;
    }
    this.rejectAll(error);
    this.terminateWorker();
  }

  private terminateWorker(): void {
    if (!this.worker) return;
    this.worker.onmessage = null;
    this.worker.onerror = null;
    this.worker.terminate();
    this.worker = null;
  }

  private rejectAll(error: unknown): void {
    for (const requestId of [...this.pending.keys()]) this.rejectPending(requestId, error);
  }

  private resolvePending<T>(requestId: string, value: T): void {
    const request = this.pending.get(requestId) as PendingRequest<T> | undefined;
    if (!request) return;
    this.pending.delete(requestId);
    request.resolve(value);
    if (request.kind === 'parse') this.activeParse = null;
  }

  private rejectPending(requestId: string, error: unknown): void {
    const request = this.pending.get(requestId);
    if (!request) return;
    this.pending.delete(requestId);
    request.reject(error);
    if (request.kind === 'parse') this.activeParse = null;
  }

  private newRequestId(): string {
    return `request-${this.nextRequestNumber++}`;
  }

  private requestIdOf(value: unknown): string | null {
    if (!value || typeof value !== 'object') return null;
    const requestId = (value as { requestId?: unknown }).requestId;
    return typeof requestId === 'string' ? requestId : null;
  }
}

export type { WorkerRequest, WorkerResponse } from './messages';
