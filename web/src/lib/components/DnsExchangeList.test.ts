import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import type { DnsExchange, Observation } from '../model';
import DnsExchangeList from './DnsExchangeList.svelte';

const exchanges: DnsExchange[] = [
  {
    id: 'dns-exchange-1',
    question: { name: 'example.com', type: 1, class: 1 },
    queryPacketNumber: 1,
    responsePacketNumber: 2,
    responseCode: 'NOERROR',
    answers: [
      { name: 'example.com', type: 1, class: 1, value: '192.0.2.53' },
      { name: 'example.com', type: 28, class: 1, value: '2001:db8::35' },
    ],
    latencyNs: '500000000',
    matched: true,
  },
  {
    id: 'dns-exchange-2',
    question: { name: 'missing.example', type: 28, class: 1 },
    queryPacketNumber: 3,
    responsePacketNumber: null,
    responseCode: null,
    answers: [],
    latencyNs: null,
    matched: false,
  },
];

const observations: Observation[] = [
  {
    id: 'observation-1',
    type: 'dns-error',
    message: 'DNS response returned NXDOMAIN',
    packetNumbers: [5, 6],
    limitation: 'Only packets in this capture were considered.',
  },
];

describe('DnsExchangeList', () => {
  it('renders the empty state', () => {
    render(DnsExchangeList, {
      props: { exchanges: [], observations: [], onSelectPacket: () => {} },
    });
    expect(screen.getByRole('heading', { name: 'DNS exchanges' })).toBeVisible();
    expect(screen.getByText(/no dns exchanges were found/i)).toBeVisible();
  });

  it('renders matched, unmatched, answer, latency, and response states', () => {
    render(DnsExchangeList, {
      props: { exchanges, observations, onSelectPacket: () => {} },
    });
    expect(screen.getByRole('heading', { name: 'example.com' })).toBeVisible();
    expect(screen.getByText('Matched')).toBeVisible();
    expect(screen.getByText('NOERROR')).toBeVisible();
    expect(screen.getByText('500 ms')).toBeVisible();
    expect(screen.getByText('192.0.2.53')).toBeVisible();
    expect(screen.getByText('2001:db8::35')).toBeVisible();
    expect(screen.getByRole('heading', { name: 'missing.example' })).toBeVisible();
    expect(screen.getByText('Unmatched')).toBeVisible();
    expect(screen.getByText(/no response was matched/i)).toBeVisible();
  });

  it('exposes keyboard buttons for exchange and observation evidence', async () => {
    let selected = 0;
    render(DnsExchangeList, {
      props: {
        exchanges,
        observations,
        onSelectPacket: (packetNumber) => (selected = packetNumber),
      },
    });
    const query = screen.getByRole('button', {
      name: 'View query packet 1 for example.com',
    });
    query.focus();
    expect(query).toHaveFocus();
    await fireEvent.click(query);
    expect(selected).toBe(1);
    await fireEvent.click(
      screen.getByRole('button', {
        name: 'View evidence packet 6 for DNS response returned NXDOMAIN',
      }),
    );
    expect(selected).toBe(6);
    expect(screen.getByText('Only packets in this capture were considered.')).toBeVisible();
  });
});
