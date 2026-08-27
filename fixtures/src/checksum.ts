/** Compute an Internet checksum over a byte range. */
export function internetChecksum(
  bytes: Uint8Array,
  start = 0,
  length = bytes.length - start,
): number {
  let sum = 0;
  const end = start + length;
  let offset = start;
  while (offset + 1 < end) {
    sum += (bytes[offset] << 8) | bytes[offset + 1];
    sum = (sum & 0xffff) + (sum >>> 16);
    offset += 2;
  }
  if (offset < end) {
    sum += bytes[offset] << 8;
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
  return ~sum & 0xffff;
}

export function writeInternetChecksum(
  bytes: Uint8Array,
  offset: number,
  start: number,
  length: number,
): void {
  bytes[offset] = 0;
  bytes[offset + 1] = 0;
  const checksum = internetChecksum(bytes, start, length);
  bytes[offset] = checksum >>> 8;
  bytes[offset + 1] = checksum & 0xff;
}

export function tcpChecksum(
  frame: Uint8Array,
  ipOffset: number,
  tcpOffset: number,
  tcpLength: number,
): number {
  const pseudo = new Uint8Array(12 + tcpLength);
  pseudo.set(frame.slice(ipOffset + 12, ipOffset + 20), 0);
  pseudo.set(frame.slice(ipOffset + 16, ipOffset + 20), 4);
  pseudo[9] = 6;
  pseudo[10] = tcpLength >>> 8;
  pseudo[11] = tcpLength & 0xff;
  pseudo.set(frame.slice(tcpOffset, tcpOffset + tcpLength), 12);
  return internetChecksum(pseudo);
}
