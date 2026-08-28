import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

export const BENCHMARK_PROFILES = [
  { name: 'small', packetCount: 3 },
  { name: 'medium', packetCount: 1024 },
  { name: 'limit-near', packetCount: 65_535 },
] as const;

export type BenchmarkProfile = (typeof BENCHMARK_PROFILES)[number];

export interface BenchmarkCapture {
  profile: BenchmarkProfile['name'];
  packetCount: number;
  bytes: Uint8Array;
}

const ETHERNET_LENGTH = 14;
const IPV4_LENGTH = 20;
const TCP_LENGTH = 20;
const PROTOCOL_FRAME_LENGTH = ETHERNET_LENGTH + IPV4_LENGTH + TCP_LENGTH;

function writeU16(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = (value >>> 8) & 0xff;
  bytes[offset + 1] = value & 0xff;
}

function writeU16Le(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
}

function writeU32Le(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}

function writeU32Be(bytes: Uint8Array, offset: number, value: number): void {
  bytes[offset] = (value >>> 24) & 0xff;
  bytes[offset + 1] = (value >>> 16) & 0xff;
  bytes[offset + 2] = (value >>> 8) & 0xff;
  bytes[offset + 3] = value & 0xff;
}

/** Build a classic little-endian microsecond PCAP without opening a network socket. */
export function buildBenchmarkCapture(profile: BenchmarkProfile): BenchmarkCapture {
  // The limit-near profile uses minimal Ethernet/ARP frames. This exercises the
  // packet-count boundary without creating hundreds of megabytes of repeated
  // protocol JSON in a result artifact.
  const frameLength = profile.name === 'limit-near' ? ETHERNET_LENGTH : PROTOCOL_FRAME_LENGTH;
  const recordLength = 16 + frameLength;
  const bytes = new Uint8Array(24 + profile.packetCount * recordLength);
  bytes.set([0xd4, 0xc3, 0xb2, 0xa1], 0);
  writeU16Le(bytes, 4, 2);
  writeU16Le(bytes, 6, 4);
  writeU32Le(bytes, 16, 65_535);
  writeU32Le(bytes, 20, 1);

  for (let packet = 0; packet < profile.packetCount; packet += 1) {
    const record = 24 + packet * recordLength;
    writeU32Le(bytes, record + 4, packet % 1_000_000);
    writeU32Le(bytes, record + 8, frameLength);
    writeU32Le(bytes, record + 12, frameLength);

    const frame = record + 16;
    const clientToServer = packet % 2 === 0;
    bytes.set(
      clientToServer ? [2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1] : [2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2],
      frame,
    );
    if (frameLength === ETHERNET_LENGTH) {
      writeU16(bytes, frame + 12, 0x0806);
      continue;
    }
    bytes.set([0x08, 0x00], frame + ETHERNET_LENGTH - 2);
    const ip = frame + ETHERNET_LENGTH;
    bytes[ip] = 0x45;
    writeU16(bytes, ip + 2, IPV4_LENGTH + TCP_LENGTH);
    writeU16(bytes, ip + 4, packet & 0xffff);
    writeU16(bytes, ip + 6, 0x4000);
    bytes[ip + 8] = 64;
    bytes[ip + 9] = 6;
    bytes.set(
      clientToServer ? [192, 0, 2, 10, 198, 51, 100, 20] : [198, 51, 100, 20, 192, 0, 2, 10],
      ip + 12,
    );
    const tcp = ip + IPV4_LENGTH;
    writeU16(bytes, tcp, clientToServer ? 51_515 : 443);
    writeU16(bytes, tcp + 2, clientToServer ? 443 : 51_515);
    writeU32Be(bytes, tcp + 4, packet);
    bytes[tcp + 12] = 0x50;
    bytes[tcp + 13] = 0x10;
    writeU16(bytes, tcp + 14, 65_535);
  }
  return { profile: profile.name, packetCount: profile.packetCount, bytes };
}

/** Generate benchmark captures to a caller-selected directory. */
export async function writeBenchmarkCaptures(directory: string): Promise<BenchmarkCapture[]> {
  const captures = BENCHMARK_PROFILES.map(buildBenchmarkCapture);
  await mkdir(resolve(directory), { recursive: true });
  await Promise.all(
    captures.map((capture) =>
      writeFile(resolve(directory, `${capture.profile}.pcap`), capture.bytes),
    ),
  );
  return captures;
}
