import type {
  CaptureDocument,
  DnsExchange,
  DnsRecord,
  Endpoint,
  HttpExchange,
  TlsHandshake,
} from './model';

export type SearchDocument = Pick<
  CaptureDocument,
  'packets' | 'endpoints' | 'dnsExchanges' | 'httpExchanges' | 'tlsHandshakes'
>;

export interface SearchIndexEntry {
  packetNumber: number;
  /** Only the allowlisted fields used by the search grammar are retained. */
  fields: {
    packetNumber: string;
    ip: string[];
    hostname: string[];
    port: string[];
    protocol: string[];
    path: string[];
  };
  text: string;
}

export interface SearchIndex {
  entries: SearchIndexEntry[];
}

export interface SearchMatch {
  packetNumber: number;
}

const protocols = new Set(['ETHERNET', 'IPV4', 'IPV6', 'TCP', 'UDP', 'DNS', 'HTTP', 'TLS']);

function hasUnsafeCharacters(value: string): boolean {
  return [...value].some((character) => {
    const code = character.charCodeAt(0);
    return (code >= 0 && code <= 31) || code === 127 || /\s/.test(character);
  });
}

function parseIpv4(value: string): number[] | null {
  const parts = value.split('.');
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return null;
  const result = parts.map(Number);
  return result.every(
    (part, index) => part <= 255 && (parts[index] === '0' || !parts[index].startsWith('0')),
  )
    ? result
    : null;
}

function parseIpv6(value: string): number[] | null {
  if (!value || value.includes('%') || value.includes(':::')) return null;
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const parseHalf = (half: string): number[] | null => {
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
  const left = parseHalf(halves[0]);
  const right = parseHalf(halves[1] ?? '');
  if (!left || !right) return null;
  if (halves.length === 1) return left.length === 8 ? left : null;
  if (left.length + right.length >= 8) return null;
  return [...left, ...Array.from({ length: 8 - left.length - right.length }, () => 0), ...right];
}

function isIp(value: string): boolean {
  return parseIpv4(value) !== null || parseIpv6(value) !== null;
}

function normalizeIp(value: string): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!isIp(trimmed)) return null;
  return trimmed.toLowerCase();
}

/** Keep only a DNS hostname or IP literal. This rejects arbitrary payload text. */
export function normalizeHostname(value: string): string | null {
  if (typeof value !== 'string') return null;
  let hostname = value.trim().toLowerCase();
  if (!hostname || hasUnsafeCharacters(hostname) || /[/?#]/.test(hostname)) return null;
  if (hostname.endsWith('.')) hostname = hostname.slice(0, -1);
  if (!hostname) return null;
  if (hostname.startsWith('[') && hostname.endsWith(']')) hostname = hostname.slice(1, -1);
  const hostWithPort = hostname.match(/^(.+):(\d+)$/);
  if (hostWithPort && !hostname.includes('::')) {
    const port = Number(hostWithPort[2]);
    if (!Number.isSafeInteger(port) || port > 65535) return null;
    hostname = hostWithPort[1];
  }
  if (isIp(hostname)) return hostname;
  if (hostname.length > 253 || hostname.startsWith('.') || hostname.endsWith('.')) return null;
  const labels = hostname.split('.');
  if (
    labels.some(
      (label) => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
    )
  ) {
    return null;
  }
  return hostname;
}

/** Remove query and fragment values before a path enters the index. */
export function sanitizeHttpPath(value: string): string | null {
  if (typeof value !== 'string') return null;
  const target = value.trim();
  if (!target || hasUnsafeCharacters(target)) return null;
  let path = target;
  if (!path.startsWith('/')) {
    const scheme = path.match(/^[a-z][a-z\d+.-]*:\/\/[^/]*(\/.*)?$/i);
    if (!scheme) return null;
    path = scheme[1] ?? '/';
  }
  path = path.split(/[?#]/, 1)[0];
  return path.startsWith('/') && path.length <= 4096 ? path.toLowerCase() : null;
}

function addUnique(values: string[], value: string | null): void {
  if (value && !values.includes(value)) values.push(value);
}

function addPacketEvidence(
  index: Map<number, SearchIndexEntry>,
  packetNumber: number | null,
  fn: (entry: SearchIndexEntry) => void,
): void {
  if (typeof packetNumber !== 'number' || !Number.isSafeInteger(packetNumber) || packetNumber < 1)
    return;
  const entry = index.get(packetNumber);
  if (entry) fn(entry);
}

function safeDnsAnswer(record: DnsRecord): string | null {
  // A and AAAA records must be IP literals. Name-bearing records use the same
  // strict hostname validator. Unknown record types are never indexed.
  if (record.type === 1 || record.type === 28) return normalizeIp(record.value);
  if (record.type === 2 || record.type === 5 || record.type === 12 || record.type === 15) {
    return normalizeHostname(record.value);
  }
  return null;
}

function addDnsEvidence(index: Map<number, SearchIndexEntry>, exchange: DnsExchange): void {
  const names: string[] = [];
  addUnique(names, normalizeHostname(exchange.question.name));
  for (const answer of exchange.answers ?? []) {
    addUnique(names, normalizeHostname(answer.name));
    const answerValue = safeDnsAnswer(answer);
    addPacketEvidence(index, exchange.responsePacketNumber, (entry) => {
      if (answerValue && isIp(answerValue)) addUnique(entry.fields.ip, answerValue);
      else addUnique(entry.fields.hostname, answerValue);
    });
  }
  for (const packetNumber of [exchange.queryPacketNumber, exchange.responsePacketNumber]) {
    addPacketEvidence(index, packetNumber, (entry) => {
      for (const name of names) addUnique(entry.fields.hostname, name);
    });
  }
}

function addHttpEvidence(index: Map<number, SearchIndexEntry>, exchange: HttpExchange): void {
  const request = exchange.request;
  if (!request) return;
  const host = (request.headers ?? []).find(
    (header) =>
      typeof header.name === 'string' &&
      header.name.toLowerCase() === 'host' &&
      !header.redacted &&
      typeof header.value === 'string' &&
      header.value.length > 0,
  );
  const hostname = host?.value ? normalizeHostname(host.value) : null;
  const path = sanitizeHttpPath(request.target);
  for (const packetNumber of request.packetNumbers ?? []) {
    addPacketEvidence(index, packetNumber, (entry) => {
      addUnique(entry.fields.hostname, hostname);
      addUnique(entry.fields.path, path);
    });
  }
}

function addTlsEvidence(index: Map<number, SearchIndexEntry>, handshake: TlsHandshake): void {
  const hostname = handshake.clientHello?.serverName
    ? normalizeHostname(handshake.clientHello.serverName)
    : null;
  for (const packetNumber of handshake.clientHello?.packetNumbers ?? []) {
    addPacketEvidence(index, packetNumber, (entry) => addUnique(entry.fields.hostname, hostname));
  }
}

function entryText(entry: SearchIndexEntry): string {
  return [
    entry.fields.packetNumber,
    ...entry.fields.ip,
    ...entry.fields.hostname,
    ...entry.fields.port,
    ...entry.fields.protocol,
    ...entry.fields.path,
  ].join(' ');
}

export function buildSearchIndex(document: SearchDocument): SearchIndex {
  const endpointById = new Map(document.endpoints.map((endpoint) => [endpoint.id, endpoint]));
  const index = new Map<number, SearchIndexEntry>();
  for (const packet of document.packets) {
    if (!Number.isSafeInteger(packet.number) || packet.number < 1) continue;
    const fields = {
      packetNumber: String(packet.number),
      ip: [],
      hostname: [],
      port: [],
      protocol: [],
      path: [],
    };
    const endpoints = [packet.sourceEndpointId, packet.destinationEndpointId]
      .map((id) => (id ? endpointById.get(id) : undefined))
      .filter((endpoint): endpoint is Endpoint => endpoint !== undefined);
    for (const endpoint of endpoints) {
      addUnique(fields.ip, normalizeIp(endpoint.address));
      if (Number.isSafeInteger(endpoint.port) && endpoint.port >= 0 && endpoint.port <= 65535) {
        addUnique(fields.port, String(endpoint.port));
      }
    }
    for (const layer of packet.layers) {
      if (protocols.has(layer.protocol)) addUnique(fields.protocol, layer.protocol.toLowerCase());
    }
    const entry = { packetNumber: packet.number, fields, text: '' };
    entry.text = entryText(entry);
    index.set(packet.number, entry);
  }
  for (const exchange of document.dnsExchanges) addDnsEvidence(index, exchange);
  for (const exchange of document.httpExchanges) addHttpEvidence(index, exchange);
  for (const handshake of document.tlsHandshakes) addTlsEvidence(index, handshake);
  for (const entry of index.values()) entry.text = entryText(entry);
  return { entries: [...index.values()].sort((a, b) => a.packetNumber - b.packetNumber) };
}

export function searchPackets(index: SearchIndex, query: string): SearchMatch[];
export function searchPackets(document: SearchDocument, query: string): SearchMatch[];
export function searchPackets(
  indexOrDocument: SearchIndex | SearchDocument,
  query: string,
): SearchMatch[] {
  const index = 'entries' in indexOrDocument ? indexOrDocument : buildSearchIndex(indexOrDocument);
  const terms = query.trim().toLowerCase() ? query.trim().toLowerCase().split(/\s+/) : [];
  if (terms.length === 0) return [];
  return index.entries
    .filter((entry) => terms.every((term) => entry.text.includes(term)))
    .map(({ packetNumber }) => ({ packetNumber }));
}

export const searchDocument = searchPackets;
export const createSearchIndex = buildSearchIndex;
