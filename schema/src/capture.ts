export type DecimalString = string;

export interface ByteRange {
  captureOffset: number;
  packetOffset: number;
  length: number;
}

export interface CaptureDocument {
  schema: 'wirelens.capture';
  contractVersion: '2.0.0';
  capture: {
    format: 'pcap' | 'pcapng';
    timestampResolution: 'microseconds' | 'nanoseconds' | 'binary' | 'custom' | 'mixed';
    packetCount: number;
    capturedBytes: number;
    originalBytes: number;
    startTimestampNs: DecimalString | null;
    endTimestampNs: DecimalString | null;
    durationNs: DecimalString;
    interfaces: CaptureInterface[];
    [key: string]: unknown;
  };
  endpoints: Endpoint[];
  packets: Packet[];
  flows: Array<TcpFlow | UdpFlow>;
  dnsExchanges: DnsExchange[];
  observations: Observation[];
  diagnostics: ParseDiagnostic[];
  [key: string]: unknown;
}

export interface ParseError {
  code:
    | 'FILE_TOO_LARGE'
    | 'PACKET_LIMIT_EXCEEDED'
    | 'TRUNCATED_GLOBAL_HEADER'
    | 'UNSUPPORTED_MAGIC'
    | 'UNSUPPORTED_VERSION'
    | 'UNSUPPORTED_LINK_TYPE'
    | 'TRUNCATED_PACKET_HEADER'
    | 'INVALID_PACKET_LENGTH'
    | 'INVALID_TIMESTAMP'
    | 'TRUNCATED_PACKET_DATA'
    | 'TRUNCATED_PCAPNG_BLOCK'
    | 'TRUNCATED_PCAPNG_SECTION'
    | 'INVALID_PCAPNG_BYTE_ORDER'
    | 'INVALID_PCAPNG_BLOCK_LENGTH'
    | 'MISMATCHED_PCAPNG_BLOCK_LENGTH'
    | 'UNSUPPORTED_PCAPNG_VERSION'
    | 'INVALID_PCAPNG_SNAPLEN'
    | 'TRUNCATED_PCAPNG_OPTION'
    | 'INVALID_PCAPNG_OPTION_LENGTH'
    | 'MISSING_PCAPNG_OPTION_END'
    | 'TRUNCATED_PCAPNG_INTERFACE'
    | 'TRUNCATED_PCAPNG_PACKET'
    | 'INVALID_PCAPNG_INTERFACE'
    | 'INVALID_PCAPNG_PACKET_LENGTH'
    | 'PCAPNG_BLOCK_LIMIT_EXCEEDED'
    | 'PCAPNG_INTERFACE_LIMIT_EXCEEDED'
    | 'PCAPNG_SECTION_REQUIRED'
    | 'PCAPNG_PACKET_EXCEEDS_SNAPLEN'
    | 'PCAP_PACKET_EXCEEDS_SNAPLEN';
  message: string;
  captureOffset: number | null;
  packetNumber: number | null;
}

export interface CaptureInterface {
  id: number;
  linkType: number;
  snapLength: number;
  timestampResolution: 'microseconds' | 'nanoseconds' | 'binary' | 'custom';
  [key: string]: unknown;
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
  interfaceId: number | null;
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

export interface UdpFlow {
  id: string;
  protocol: 'UDP';
  clientEndpointId: string;
  serverEndpointId: string;
  startTimestampNs: DecimalString | null;
  endTimestampNs: DecimalString | null;
  packetNumbers: number[];
  capturedBytes: number;
  originalBytes: number;
  [key: string]: unknown;
}

export interface DnsQuestion {
  name: string;
  type: number;
  class: number;
  [key: string]: unknown;
}

export interface DnsRecord {
  name: string;
  type: number;
  class: number;
  value: string;
  [key: string]: unknown;
}

export interface DnsExchange {
  id: string;
  question: DnsQuestion;
  queryPacketNumber: number | null;
  responsePacketNumber: number | null;
  responseCode: string | null;
  answers: DnsRecord[];
  latencyNs: DecimalString | null;
  matched: boolean;
  [key: string]: unknown;
}

export interface Observation {
  id: string;
  type: string;
  message: string;
  packetNumbers: number[];
  limitation: string;
  [key: string]: unknown;
}

export interface ParseDiagnostic {
  severity: 'info' | 'warning' | 'error';
  code: string;
  message: string;
  context: string;
  captureOffset: number | null;
  packetNumber: number | null;
  count: number | null;
  [key: string]: unknown;
}
