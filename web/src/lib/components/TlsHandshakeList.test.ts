import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import type { TlsHandshake } from '../model';
import TlsHandshakeList from './TlsHandshakeList.svelte';

const handshakes: TlsHandshake[] = [
  {
    id: 'tls-handshake-1',
    flowId: 'tcp-flow-1',
    clientHello: {
      recordVersion: 'TLS 1.0',
      legacyVersion: 'TLS 1.2',
      offeredVersions: ['TLS 1.3', 'TLS 1.2'],
      serverName: 'secure.example.test',
      packetNumbers: [7],
    },
    serverHello: {
      recordVersion: 'TLS 1.2',
      legacyVersion: 'TLS 1.2',
      negotiatedVersion: 'TLS 1.3',
      packetNumbers: [8],
    },
    matched: true,
    limitation: 'WireLens does not decrypt TLS application data.',
  },
  {
    id: 'tls-handshake-2',
    flowId: 'tcp-flow-2',
    clientHello: {
      recordVersion: 'TLS 1.2',
      legacyVersion: 'TLS 1.2',
      offeredVersions: ['TLS 1.2'],
      serverName: null,
      packetNumbers: [9],
    },
    serverHello: null,
    matched: false,
    limitation: 'WireLens does not decrypt TLS application data.',
  },
];

describe('TlsHandshakeList', () => {
  it('renders the empty state', () => {
    render(TlsHandshakeList, { props: { handshakes, onSelectPacket: () => {} } });
    expect(screen.getByRole('heading', { name: 'TLS handshakes' })).toBeVisible();
  });

  it('renders ClientHello and ServerHello metadata and the decryption limitation', () => {
    render(TlsHandshakeList, { props: { handshakes, onSelectPacket: () => {} } });
    expect(screen.getAllByText('Matched')).toHaveLength(1);
    expect(screen.getByText('Unmatched')).toBeVisible();
    expect(screen.getByText('TLS 1.3')).toBeVisible();
    expect(screen.getByText('secure.example.test')).toBeVisible();
    expect(screen.getByText('Not visible')).toBeVisible();
    expect(screen.getAllByText('WireLens does not decrypt TLS application data.')).toHaveLength(2);
  });

  it('provides packet evidence buttons for hello messages', async () => {
    let selected = 0;
    render(TlsHandshakeList, {
      props: { handshakes: [handshakes[0]], onSelectPacket: (number) => (selected = number) },
    });
    const client = screen.getByRole('button', { name: 'View TLS ClientHello packet 7' });
    client.focus();
    expect(client).toHaveFocus();
    await fireEvent.click(client);
    expect(selected).toBe(7);
    await fireEvent.click(screen.getByRole('button', { name: 'View TLS ServerHello packet 8' }));
    expect(selected).toBe(8);
  });

  it('renders an explicit empty message', () => {
    render(TlsHandshakeList, { props: { handshakes: [], onSelectPacket: () => {} } });
    expect(screen.getByText(/no TLS handshakes were found/i)).toBeVisible();
  });
});
