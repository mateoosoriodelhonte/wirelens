import { describe, expect, it } from 'vitest';
import { learningTextFor, tcpEventLearningText } from './learning';

describe('learning text catalog', () => {
  it.each([
    ['ETHERNET', null, 'Ethernet carries this frame across the local link.'],
    ['IPV4', null, 'IPv4 identifies the source and destination network addresses.'],
    ['IPV6', null, 'IPv6 identifies the source and destination network addresses.'],
    ['TCP', 'tcp', 'TCP provides an ordered connection between two endpoints.'],
    ['UDP', null, 'UDP carries one datagram without a connection handshake.'],
    ['DNS', 'dns', 'DNS maps names and network addresses.'],
    ['HTTP', 'http', 'HTTP headers describe a plaintext request or response.'],
    ['TLS', 'tls', 'TLS handshake metadata describes encrypted-session setup.'],
  ])('returns reviewed text for %s', (protocol, explanationKey, expected) => {
    expect(learningTextFor(protocol, explanationKey)).toBe(expected);
  });

  it('uses keyed TCP event text and a neutral fallback', () => {
    expect(tcpEventLearningText('SYN + ACK')).toBe(
      'The server accepts and acknowledges the client request.',
    );
    expect(tcpEventLearningText('UNRECOGNIZED')).toBe(
      'This packet carries TCP connection evidence.',
    );
    expect(learningTextFor('UNKNOWN', null)).toBe(
      'This field describes evidence in the selected protocol layer.',
    );
  });
});
