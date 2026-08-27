export type DecimalString = string;

export interface ByteRange {
  captureOffset: number;
  packetOffset: number;
  length: number;
}

export interface CaptureDocument {
  schema: 'wirelens.capture';
  contractVersion: '1.0.0';
  capture: {
    format: 'pcap';
    timestampResolution: 'microseconds' | 'nanoseconds';
    packetCount: number;
    capturedBytes: number;
    originalBytes: number;
    startTimestampNs: DecimalString | null;
    endTimestampNs: DecimalString | null;
    durationNs: DecimalString;
    [key: string]: unknown;
  };
  endpoints: Endpoint[];
  packets: Packet[];
  flows: TcpFlow[];
  diagnostics: ParseDiagnostic[];
  [key: string]: unknown;
}

export interface ParseError {
  code:
    | 'FILE_TOO_LARGE'
    | 'TRUNCATED_GLOBAL_HEADER'
    | 'UNSUPPORTED_MAGIC'
    | 'UNSUPPORTED_VERSION'
    | 'UNSUPPORTED_LINK_TYPE'
    | 'TRUNCATED_PACKET_HEADER'
    | 'INVALID_PACKET_LENGTH'
    | 'TRUNCATED_PACKET_DATA';
  message: string;
  captureOffset: number | null;
  packetNumber: number | null;
}

export interface Endpoint {
  id: string;
  address: string;
  port: number;
  addressFamily: 'ipv4' | 'ipv6' | 'unknown';
  [key: string]: unknown;
}
export type ProtocolName =
  'ETHERNET' | 'IPV4' | 'IPV6' | 'TCP' | 'UDP' | 'DNS' | 'HTTP' | 'TLS' | 'UNKNOWN';
export interface ProtocolField {
  name: string;
  value: string;
  byteRange: ByteRange | null;
  explanationKey: string | null;
  [key: string]: unknown;
}
export interface ProtocolLayer {
  protocol: ProtocolName;
  label: string;
  fields: ProtocolField[];
  byteRange: ByteRange | null;
  explanationKey: string | null;
  [key: string]: unknown;
}
export interface Packet {
  id: string;
  number: number;
  timestampNs: DecimalString;
  capturedLength: number;
  originalLength: number;
  sourceEndpointId: string | null;
  destinationEndpointId: string | null;
  summary: string;
  layers: ProtocolLayer[];
  flowId: string | null;
  analysisFlags: string[];
  [key: string]: unknown;
}
export interface TcpFlowEvent {
  packetNumber: number;
  label: 'SYN' | 'SYN + ACK' | 'ACK' | 'FIN' | 'FIN + ACK' | 'RST' | 'DATA';
  [key: string]: unknown;
}
export interface TcpFlow {
  id: string;
  protocol: 'TCP';
  clientEndpointId: string;
  serverEndpointId: string;
  startTimestampNs: DecimalString | null;
  endTimestampNs: DecimalString | null;
  packetNumbers: number[];
  capturedBytes: number;
  originalBytes: number;
  handshake: 'complete' | 'partial' | 'unobserved';
  termination: 'graceful' | 'reset' | 'open-at-capture-end' | 'unknown';
  events: TcpFlowEvent[];
  [key: string]: unknown;
}
export interface ParseDiagnostic {
  severity: 'info' | 'warning' | 'error';
  code: string;
  message: string;
  context: string;
  captureOffset: number | null;
  packetNumber: number | null;
  [key: string]: unknown;
}
