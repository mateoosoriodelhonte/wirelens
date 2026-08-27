import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import PacketDetails from './PacketDetails.svelte';
import { demoDocument } from '../demo-document';
import type { Packet } from '../model';

describe('PacketDetails', () => {
  it('shows protocol layer headings and the SYN explanation', () => {
    render(PacketDetails, { props: { packet: demoDocument.packets[0], learningMode: true } });
    expect(screen.getByRole('heading', { name: /ethernet/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /ipv4/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /tcp/i })).toBeInTheDocument();
    expect(screen.getByText(/synchronize sequence numbers/i)).toBeInTheDocument();
  });

  it('derives TCP and SYN learning text from a schema-exact lowercase flags field', () => {
    const packet: Packet = {
      id: 'packet-1',
      number: 1,
      timestampNs: '1000000000',
      capturedLength: 54,
      originalLength: 54,
      sourceEndpointId: 'endpoint-client',
      destinationEndpointId: 'endpoint-server',
      flowId: 'tcp-flow-1',
      analysisFlags: [],
      summary: 'SYN',
      layers: [
        {
          protocol: 'ETHERNET',
          label: 'Ethernet II',
          fields: [],
          byteRange: null,
          explanationKey: null,
        },
        { protocol: 'IPV4', label: 'IPv4', fields: [], byteRange: null, explanationKey: null },
        {
          protocol: 'TCP',
          label: 'TCP',
          fields: [{ name: 'flags', value: 'SYN', byteRange: null, explanationKey: null }],
          byteRange: null,
          explanationKey: null,
        },
      ],
    };
    render(PacketDetails, { props: { packet, learningMode: true } });
    expect(screen.getByText('TCP', { selector: '.protocol-tag' })).toBeInTheDocument();
    expect(screen.getByText(/synchronize sequence numbers/i)).toBeInTheDocument();
  });
});
