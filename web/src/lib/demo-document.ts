import type { CaptureDocument, Packet, ProtocolLayer } from './model';

const client = '192.0.2.10';
const server = '198.51.100.20';
const clientId = 'endpoint-client';
const serverId = 'endpoint-server';
const flowId = 'tcp-flow-1';

const layer = (
  protocol: ProtocolLayer['protocol'],
  label: string,
  fields: ProtocolLayer['fields'],
  explanationKey: string | null = null,
): ProtocolLayer => ({ protocol, label, fields, byteRange: null, explanationKey });
const field = (name: string, value: string, explanationKey: string | null = null) => ({
  name,
  value,
  byteRange: null,
  explanationKey,
});

const packets: Packet[] = [
  {
    id: 'packet-1',
    number: 1,
    timestampNs: '1000000000',
    capturedLength: 54,
    originalLength: 54,
    interfaceId: 0,
    sourceEndpointId: clientId,
    destinationEndpointId: serverId,
    flowId,
    analysisFlags: [],
    summary: 'SYN · start a TCP connection',
    layers: [
      layer('ETHERNET', 'Ethernet II', [field('Type', 'IPv4')]),
      layer('IPV4', `${client} → ${server}`, [
        field('Source', client),
        field('Destination', server),
      ]),
      layer(
        'TCP',
        '51515 → 443 · SYN',
        [field('Flags', 'SYN', 'tcp.syn'), field('Sequence number', '1000')],
        'tcp',
      ),
    ],
  },
  {
    id: 'packet-2',
    number: 2,
    timestampNs: '1010000000',
    capturedLength: 54,
    originalLength: 54,
    interfaceId: 0,
    sourceEndpointId: serverId,
    destinationEndpointId: clientId,
    flowId,
    analysisFlags: [],
    summary: 'SYN + ACK · accept the connection',
    layers: [
      layer('ETHERNET', 'Ethernet II', [field('Type', 'IPv4')]),
      layer('IPV4', `${server} → ${client}`, [
        field('Source', server),
        field('Destination', client),
      ]),
      layer(
        'TCP',
        '443 → 51515 · SYN + ACK',
        [
          field('Flags', 'SYN + ACK', 'tcp.syn-ack'),
          field('Sequence number', '5000'),
          field('Acknowledgement', '1001'),
        ],
        'tcp',
      ),
    ],
  },
  {
    id: 'packet-3',
    number: 3,
    timestampNs: '1020000000',
    capturedLength: 54,
    originalLength: 54,
    interfaceId: 0,
    sourceEndpointId: clientId,
    destinationEndpointId: serverId,
    flowId,
    analysisFlags: [],
    summary: 'ACK · complete the handshake',
    layers: [
      layer('ETHERNET', 'Ethernet II', [field('Type', 'IPv4')]),
      layer('IPV4', `${client} → ${server}`, [
        field('Source', client),
        field('Destination', server),
      ]),
      layer(
        'TCP',
        '51515 → 443 · ACK',
        [
          field('Flags', 'ACK', 'tcp.ack'),
          field('Sequence number', '1001'),
          field('Acknowledgement', '5001'),
        ],
        'tcp',
      ),
    ],
  },
];

export const demoDocument: CaptureDocument = {
  schema: 'wirelens.capture',
  contractVersion: '2.0.0',
  capture: {
    format: 'pcap',
    timestampResolution: 'microseconds',
    packetCount: 3,
    capturedBytes: 162,
    originalBytes: 162,
    startTimestampNs: '1000000000',
    endTimestampNs: '1020000000',
    durationNs: '20000000',
    interfaces: [{ id: 0, linkType: 1, snapLength: 0, timestampResolution: 'microseconds' }],
  },
  endpoints: [
    { id: clientId, address: client, port: 51515, addressFamily: 'ipv4' },
    { id: serverId, address: server, port: 443, addressFamily: 'ipv4' },
  ],
  packets,
  flows: [
    {
      id: flowId,
      protocol: 'TCP',
      clientEndpointId: clientId,
      serverEndpointId: serverId,
      startTimestampNs: '1000000000',
      endTimestampNs: '1020000000',
      packetNumbers: [1, 2, 3],
      capturedBytes: 162,
      originalBytes: 162,
      handshake: 'complete',
      midStream: false,
      termination: 'open-at-capture-end',
      events: [
        { packetNumber: 1, label: 'SYN' },
        { packetNumber: 2, label: 'SYN + ACK' },
        { packetNumber: 3, label: 'ACK' },
      ],
    },
  ],
  dnsExchanges: [],
  observations: [],
  diagnostics: [],
};
