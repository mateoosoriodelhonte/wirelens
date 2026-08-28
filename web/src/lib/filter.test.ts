import { describe, expect, it } from 'vitest';
import { demoDocument } from './demo-document';
import { applyPacketFilter, filterPackets, matchesPacketFilter, parseFilter } from './filter';

describe('packet filters', () => {
  it('parses the small, case-insensitive grammar', () => {
    const result = parseFilter('TCP ip:192.0.2.10 PORT:51515');
    expect(result).toEqual({
      ok: true,
      terms: [
        { kind: 'protocol', protocol: 'TCP' },
        { kind: 'ip', address: '192.0.2.10' },
        { kind: 'port', port: 51515 },
      ],
    });
  });

  it('accepts IPv6 literals and both port bounds', () => {
    expect(parseFilter('ip:2001:db8::1')).toMatchObject({ ok: true });
    expect(parseFilter('port:0')).toMatchObject({ ok: true });
    expect(parseFilter('port:65535')).toMatchObject({ ok: true });
  });

  it.each([
    ['ip:', 'empty-ip'],
    ['port:', 'empty-port'],
    ['ip:192.0.2.999', 'invalid-ip'],
    ['ip:2001:db8:::1', 'invalid-ip'],
    ['port:-1', 'invalid-port'],
    ['port:65536', 'invalid-port'],
    ['port:1.5', 'invalid-port'],
    ['icmp', 'unsupported-token'],
    ['tcp OR udp', 'unsupported-token'],
    ['tcp,udp', 'unsupported-token'],
  ])('rejects %j', (input, code) => {
    expect(parseFilter(input)).toMatchObject({ ok: false, error: { code } });
  });

  it('accepts a cleared filter as all terms', () => {
    expect(parseFilter('')).toEqual({ ok: true, terms: [] });
    expect(parseFilter('   ')).toEqual({ ok: true, terms: [] });
  });

  it('combines terms with logical AND over endpoint and layer facts', () => {
    const parsed = parseFilter('tcp ip:192.0.2.10 port:51515');
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(
      demoDocument.packets.filter((packet) =>
        matchesPacketFilter(packet, demoDocument.endpoints, parsed.terms),
      ),
    ).toHaveLength(3);
    expect(
      applyPacketFilter(demoDocument.packets, demoDocument.endpoints, parsed.terms),
    ).toHaveLength(3);
  });

  it('returns a typed error without retaining or changing any result set', () => {
    expect(filterPackets(demoDocument, '')).toMatchObject({
      ok: true,
      packets: demoDocument.packets,
    });
    const invalid = filterPackets(demoDocument, 'ip:not-an-address');
    expect(invalid).toMatchObject({ ok: false, error: { code: 'invalid-ip' } });
    expect(invalid).not.toHaveProperty('packets');
  });
});
