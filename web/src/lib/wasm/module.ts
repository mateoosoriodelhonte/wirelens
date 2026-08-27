export interface WasmModule {
  readonly HEAPU8: Uint8Array;
  wirelens_alloc(size: number): number;
  wirelens_parse_owned(data: number, size: number): number;
  wirelens_result_ok(handle: number): number;
  wirelens_result_data(handle: number): number;
  wirelens_result_size(handle: number): number;
  wirelens_result_error_code(handle: number): number;
  wirelens_result_error_offset(handle: number): number | bigint;
  wirelens_packet_data(handle: number, packetIndex: number): number;
  wirelens_packet_size(handle: number, packetIndex: number): number;
  wirelens_release(handle: number): void;
}

type RawWasmModule = Record<string, unknown> & { HEAPU8?: Uint8Array };

function functionExport(raw: RawWasmModule, name: string): (...args: number[]) => number {
  const value = raw[name] ?? raw[`_${name}`];
  if (typeof value !== 'function') throw new Error(`WebAssembly export ${name} is missing`);
  return value.bind(raw) as (...args: number[]) => number;
}

export function adaptWasmModule(raw: RawWasmModule): WasmModule {
  if (!(raw.HEAPU8 instanceof Uint8Array)) throw new Error('WebAssembly HEAPU8 is missing');
  const release = functionExport(raw, 'wirelens_release');
  return {
    get HEAPU8() {
      if (!(raw.HEAPU8 instanceof Uint8Array)) throw new Error('WebAssembly HEAPU8 is missing');
      return raw.HEAPU8;
    },
    wirelens_alloc: functionExport(raw, 'wirelens_alloc'),
    wirelens_parse_owned: functionExport(raw, 'wirelens_parse_owned'),
    wirelens_result_ok: functionExport(raw, 'wirelens_result_ok'),
    wirelens_result_data: functionExport(raw, 'wirelens_result_data'),
    wirelens_result_size: functionExport(raw, 'wirelens_result_size'),
    wirelens_result_error_code: functionExport(raw, 'wirelens_result_error_code'),
    wirelens_result_error_offset: functionExport(raw, 'wirelens_result_error_offset'),
    wirelens_packet_data: functionExport(raw, 'wirelens_packet_data'),
    wirelens_packet_size: functionExport(raw, 'wirelens_packet_size'),
    wirelens_release: (handle) => {
      release(handle);
    },
  };
}

export interface WasmModuleLoadOptions {
  moduleUrl?: string;
  wasmUrl?: string;
}

export async function loadWasmModule(options: WasmModuleLoadOptions = {}): Promise<WasmModule> {
  const moduleUrl = options.moduleUrl ?? '/wasm/wirelens.js';
  const wasmUrl = options.wasmUrl ?? moduleUrl.replace(/\.js(?:\?.*)?$/, '.wasm');
  const namespace = (await import(/* @vite-ignore */ moduleUrl)) as {
    default?: unknown;
  };
  const factory = namespace.default ?? namespace;
  const raw =
    typeof factory === 'function'
      ? await (
          factory as (options: Record<string, unknown>) => Promise<RawWasmModule> | RawWasmModule
        )({
          locateFile: () => wasmUrl,
        })
      : factory;
  if (!raw || typeof raw !== 'object') throw new Error('WebAssembly module did not initialize');
  return adaptWasmModule(raw as RawWasmModule);
}
