import type { CaptureDocument, Endpoint, Packet, ProtocolName } from './model';

export type FilterProtocol = Extract<ProtocolName, 'TCP' | 'UDP' | 'DNS' | 'HTTP' | 'TLS'>;

export type FilterTerm =
  | { kind: 'protocol'; protocol: FilterProtocol }
  | { kind: 'ip'; address: string }
  | { kind: 'port'; port: number };

export type FilterErrorCode =
  'empty-ip' | 'empty-port' | 'invalid-ip' | 'invalid-port' | 'unsupported-token';

export interface FilterParseError {
  code: FilterErrorCode;
  message: string;
  token: string;
  index: number;
}

export type FilterParseResult =
  { ok: true; terms: FilterTerm[] } | { ok: false; error: FilterParseError };

export type FilterResult =
  { ok: true; terms: FilterTerm[]; packets: Packet[] } | { ok: false; error: FilterParseError };

const protocolNames = new Map<string, FilterProtocol>([
  ['tcp', 'TCP'],
  ['udp', 'UDP'],
  ['dns', 'DNS'],
  ['http', 'HTTP'],
  ['tls', 'TLS'],
]);

function error(
  code: FilterErrorCode,
  message: string,
  token: string,
  index: number,
): FilterParseResult {
  return { ok: false, error: { code, message, token, index } };
}

function parseIpv4(value: string): number[] | null {
  const octets = value.split('.');
  if (octets.length !== 4 || octets.some((octet) => !/^\d{1,3}$/.test(octet))) return null;
  const numbers = octets.map(Number);
  if (
    numbers.some(
      (octet, index) => octet > 255 || (octets[index] !== '0' && octets[index].startsWith('0')),
    )
  ) {
    return null;
  }
  return numbers;
}

/** Return eight 16-bit groups for a syntactically valid IPv6 literal. */
function parseIpv6(value: string): number[] | null {
  if (!value || value.includes('%') || value.includes(':::')) return null;
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const parseGroups = (half: string): number[] | null => {
    if (!half) return [];
    const parts = half.split(':');
    const groups: number[] = [];
    for (const part of parts) {
      if (part.includes('.')) {
        if (part !== parts.at(-1)) return null;
        const octets = parseIpv4(part);
        if (!octets) return null;
        groups.push((octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]);
      } else {
        if (!/^[0-9a-f]{1,4}$/i.test(part)) return null;
        groups.push(Number.parseInt(part, 16));
      }
    }
    return groups;
  };
  const left = parseGroups(halves[0]);
  const right = parseGroups(halves[1] ?? '');
  if (!left || !right) return null;
  if (halves.length === 1) return left.length === 8 ? left : null;
  if (left.length + right.length >= 8) return null;
  return [...left, ...Array.from({ length: 8 - left.length - right.length }, () => 0), ...right];
}

function parseIp(value: string): { family: 'ipv4' | 'ipv6'; groups: number[] } | null {
  const ipv4 = parseIpv4(value);
  if (ipv4) return { family: 'ipv4', groups: ipv4 };
  const ipv6 = parseIpv6(value);
  return ipv6 ? { family: 'ipv6', groups: ipv6 } : null;
}

function sameIp(left: string, right: string): boolean {
  const a = parseIp(left);
  const b = parseIp(right);
  if (!a || !b || a.family !== b.family || a.groups.length !== b.groups.length) return false;
  return a.groups.every((group, index) => group === b.groups[index]);
}

export function parseFilter(input: string): FilterParseResult {
  const terms: FilterTerm[] = [];
  const tokens = input.trim() ? input.trim().split(/\s+/) : [];
  for (const [index, token] of tokens.entries()) {
    const normalized = token.toLowerCase();
    const protocol = protocolNames.get(normalized);
    if (protocol) {
      terms.push({ kind: 'protocol', protocol });
      continue;
    }
    if (normalized.startsWith('ip:')) {
      const address = token.slice(token.indexOf(':') + 1);
      if (!address)
        return error('empty-ip', 'Enter an IPv4 or IPv6 literal after ip:', token, index);
      if (!parseIp(address))
        return error('invalid-ip', `Invalid IP address: ${address}`, token, index);
      terms.push({ kind: 'ip', address: address.toLowerCase() });
      continue;
    }
    if (normalized.startsWith('port:')) {
      const value = token.slice(token.indexOf(':') + 1);
      if (!value) return error('empty-port', 'Enter a decimal port after port:', token, index);
      if (!/^\d+$/.test(value)) {
        return error(
          'invalid-port',
          `Port must be a decimal number from 0 to 65535: ${value}`,
          token,
          index,
        );
      }
      const port = Number(value);
      if (!Number.isSafeInteger(port) || port > 65535) {
        return error(
          'invalid-port',
          `Port must be a decimal number from 0 to 65535: ${value}`,
          token,
          index,
        );
      }
      terms.push({ kind: 'port', port });
      continue;
    }
    return error(
      'unsupported-token',
      `Unsupported filter term: ${token}. Use tcp, udp, dns, http, tls, ip:<address>, or port:<number>.`,
      token,
      index,
    );
  }
  return { ok: true, terms };
}

function packetEndpoints(packet: Packet, endpoints: readonly Endpoint[]): Endpoint[] {
  const endpointById = new Map(endpoints.map((endpoint) => [endpoint.id, endpoint]));
  return [packet.sourceEndpointId, packet.destinationEndpointId]
    .map((id) => (id ? endpointById.get(id) : undefined))
    .filter((endpoint): endpoint is Endpoint => endpoint !== undefined);
}

export function matchesPacketFilter(
  packet: Packet,
  endpoints: readonly Endpoint[],
  terms: readonly FilterTerm[],
): boolean {
  const packetEndpointsList = packetEndpoints(packet, endpoints);
  return terms.every((term) => {
    if (term.kind === 'protocol')
      return packet.layers.some((layer) => layer.protocol === term.protocol);
    if (term.kind === 'ip')
      return packetEndpointsList.some((endpoint) => sameIp(endpoint.address, term.address));
    return packetEndpointsList.some((endpoint) => endpoint.port === term.port);
  });
}

export function applyPacketFilter(
  packets: readonly Packet[],
  endpoints: readonly Endpoint[],
  terms: readonly FilterTerm[],
): Packet[] {
  return packets.filter((packet) => matchesPacketFilter(packet, endpoints, terms));
}

export function filterPackets(
  document: Pick<CaptureDocument, 'packets' | 'endpoints'>,
  input: string | FilterParseResult,
): FilterResult {
  const parsed = typeof input === 'string' ? parseFilter(input) : input;
  if (!parsed.ok) return parsed;
  return {
    ok: true,
    terms: parsed.terms,
    packets: applyPacketFilter(document.packets, document.endpoints, parsed.terms),
  };
}

export const parsePacketFilter = parseFilter;
export const applyFilter = applyPacketFilter;
export const evaluateFilter = filterPackets;
