const fallbackText = 'This field describes evidence in the selected protocol layer.';

const layerText: Readonly<Record<string, string>> = {
  ethernet: 'Ethernet carries this frame across the local link.',
  ipv4: 'IPv4 identifies the source and destination network addresses.',
  ipv6: 'IPv6 identifies the source and destination network addresses.',
  tcp: 'TCP provides an ordered connection between two endpoints.',
  udp: 'UDP carries one datagram without a connection handshake.',
  dns: 'DNS maps names and network addresses.',
  http: 'HTTP headers describe a plaintext request or response.',
  tls: 'TLS handshake metadata describes encrypted-session setup.',
  'tcp.syn': 'Synchronize sequence numbers to begin a connection.',
  'tcp.syn-ack': 'The server accepts and acknowledges the client request.',
  'tcp.ack': 'This packet acknowledges TCP sequence data.',
  'tcp.fin': 'This endpoint asked to close the TCP connection.',
  'tcp.rst': 'This endpoint stopped the TCP connection.',
  'tcp.data': 'This packet carries TCP payload bytes.',
};

const tcpEventText: Readonly<Record<string, string>> = {
  SYN: 'The client asks to start a TCP connection.',
  'SYN + ACK': 'The server accepts and acknowledges the client request.',
  ACK: 'The client acknowledges the server. The handshake is complete.',
  FIN: 'One endpoint asks to close the TCP connection.',
  'FIN + ACK': 'One endpoint acknowledges traffic and asks to close the connection.',
  RST: 'One endpoint stops the TCP connection immediately.',
  DATA: 'This packet carries TCP payload bytes.',
};

export function learningTextFor(protocol: string, explanationKey: string | null): string {
  const protocolKey = protocol.toLowerCase();
  return layerText[explanationKey ?? ''] ?? layerText[protocolKey] ?? fallbackText;
}

export function tcpEventLearningText(label: string): string {
  return tcpEventText[label] ?? 'This packet carries TCP connection evidence.';
}
