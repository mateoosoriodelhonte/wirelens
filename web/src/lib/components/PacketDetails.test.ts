import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
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
      interfaceId: 0,
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

  it('does not describe reset or data packets as handshake completion', () => {
    const packet = structuredClone(demoDocument.packets[2]);
    const flags = packet.layers
      .find((layer) => layer.protocol === 'TCP')
      ?.fields.find((field) => field.name.toLowerCase() === 'flags');
    if (!flags) throw new Error('TCP flags fixture is missing');
    flags.value = 'ACK, RST';
    flags.explanationKey = 'tcp.rst';
    render(PacketDetails, { props: { packet, learningMode: true } });
    expect(screen.getByText(/stopped the TCP connection/i)).toBeInTheDocument();
    expect(screen.queryByText(/completes the handshake/i)).not.toBeInTheDocument();
  });

  it('shows reviewed learning text for every displayed protocol layer', () => {
    const packet: Packet = {
      ...structuredClone(demoDocument.packets[0]),
      layers: [
        {
          protocol: 'UDP',
          label: 'UDP',
          fields: [],
          byteRange: null,
          explanationKey: null,
        },
        {
          protocol: 'DNS',
          label: 'DNS query',
          fields: [],
          byteRange: null,
          explanationKey: 'dns',
        },
      ],
    };
    render(PacketDetails, { props: { packet, learningMode: true } });
    expect(screen.getByText(/UDP carries one datagram/i)).toBeVisible();
    expect(screen.getByText(/DNS maps names and network addresses/i)).toBeVisible();
  });

  it('offers keyboard buttons for bounded layer and field byte ranges', async () => {
    const packet = structuredClone(demoDocument.packets[0]);
    const tcp = packet.layers.find((layer) => layer.protocol === 'TCP');
    if (!tcp) throw new Error('TCP fixture is missing');
    tcp.byteRange = { captureOffset: 64, packetOffset: 34, length: 20 };
    tcp.fields[0].byteRange = { captureOffset: 76, packetOffset: 46, length: 2 };
    const onSelectByteRange = vi.fn();

    render(PacketDetails, {
      props: {
        packet,
        selectedByteRange: tcp.fields[0].byteRange,
        onSelectByteRange,
      },
    });

    const layerButton = screen.getByRole('button', { name: /show TCP layer bytes/i });
    const fieldButton = screen.getByRole('button', { name: /show Flags field bytes/i });
    expect(layerButton).toHaveAttribute('aria-pressed', 'false');
    expect(fieldButton).toHaveAttribute('aria-pressed', 'true');

    await fireEvent.click(layerButton);
    expect(onSelectByteRange).toHaveBeenCalledWith(tcp.byteRange);
    await fireEvent.click(fieldButton);
    expect(onSelectByteRange).toHaveBeenLastCalledWith(tcp.fields[0].byteRange);
  });

  it('does not create byte controls for absent ranges', () => {
    render(PacketDetails, { props: { packet: demoDocument.packets[0] } });
    expect(screen.queryByRole('button', { name: /bytes/i })).not.toBeInTheDocument();
  });
});
