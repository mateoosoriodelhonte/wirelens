import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { demoDocument } from '$lib/demo-document';

const { instances, MockParser } = vi.hoisted(() => {
  const created: Array<{ parse: ReturnType<typeof vi.fn>; dispose: ReturnType<typeof vi.fn> }> = [];
  class Parser {
    readonly parse = vi.fn();
    readonly dispose = vi.fn(async () => undefined);

    constructor() {
      created.push(this);
    }
  }
  return { instances: created, MockParser: Parser };
});

vi.mock('$lib/worker/parser-client', () => ({
  ParserClient: MockParser,
  ParseCancelledError: class ParseCancelledError extends Error {},
}));

import Page from './+page.svelte';

const capture = (name = 'handshake.pcap') => new File(['capture'], name);

beforeEach(() => {
  instances.length = 0;
});

describe('capture page', () => {
  it('starts empty and advertises only local .pcap processing', () => {
    render(Page);
    expect(
      screen.getByRole('heading', { name: /inspect a capture on this device/i }),
    ).toBeVisible();
    expect(screen.getByText(/nothing is uploaded/i)).toBeVisible();
    expect(screen.getByText(/\.pcap.*drag and drop also works/i)).toBeVisible();
    expect(screen.getByText(/\.pcap.*\.pcapng.*drag and drop also works/i)).toBeVisible();
    expect(screen.queryByText(/synthetic demo/i)).not.toBeInTheDocument();
  });

  it('shows loading then ready content and focuses the overview heading', async () => {
    render(Page);
    let resolveParse!: (document: typeof demoDocument) => void;
    instances[0].parse.mockReturnValue(
      new Promise((resolve) => {
        resolveParse = resolve;
      }),
    );
    const input = screen.getByLabelText(/capture file/i);
    await fireEvent.change(input, { target: { files: [capture()] } });
    expect(screen.getByRole('main')).toHaveAttribute('aria-busy', 'true');
    resolveParse(demoDocument);
    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /capture overview/i })).toHaveFocus(),
    );
    expect(screen.getByText('3 packets')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /conversations/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /dns exchanges/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Observations' })).toBeInTheDocument();
    expect(screen.getByText('SYN + ACK')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /ethernet/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /ipv4/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /tcp/i })).toBeInTheDocument();
    expect(screen.getByRole('main')).not.toHaveAttribute('aria-busy', 'true');
  });

  it('follows DNS evidence to the selected packet details', async () => {
    const dnsDocument = {
      ...demoDocument,
      dnsExchanges: [
        {
          id: 'dns-exchange-1',
          question: { name: 'example.com', type: 1, class: 1 },
          queryPacketNumber: 1,
          responsePacketNumber: 2,
          responseCode: 'NOERROR',
          answers: [{ name: 'example.com', type: 1, class: 1, value: '192.0.2.53' }],
          latencyNs: '10000000',
          matched: true,
        },
      ],
      observations: [],
    };
    render(Page);
    instances[0].parse.mockResolvedValue(dnsDocument);
    await fireEvent.change(screen.getByLabelText(/capture file/i), {
      target: { files: [capture('dns.pcap')] },
    });
    const evidence = await screen.findByRole('button', {
      name: 'View response packet 2 for example.com',
    });
    await fireEvent.click(evidence);
    const detailsHeading = screen.getByRole('heading', { name: 'Packet details' });
    expect(detailsHeading).toHaveFocus();
    expect(detailsHeading.closest('section')).toHaveTextContent('Packet 2');
  });

  it('follows TCP observation evidence to packet details', async () => {
    const tcpDocument = {
      ...demoDocument,
      observations: [
        {
          id: 'observation-1',
          type: 'tcp-retransmission-candidate',
          message: 'TCP segment appears to resend bytes already seen.',
          packetNumbers: [1, 2],
          limitation: 'Only packets in this capture were considered.',
        },
      ],
    };
    render(Page);
    instances[0].parse.mockResolvedValue(tcpDocument);
    await fireEvent.change(screen.getByLabelText(/capture file/i), {
      target: { files: [capture('retransmission.pcap')] },
    });
    const evidence = await screen.findByRole('button', {
      name: /view evidence packet 2 for TCP segment appears to resend bytes already seen/i,
    });
    await fireEvent.click(evidence);
    const detailsHeading = screen.getByRole('heading', { name: 'Packet details' });
    expect(detailsHeading).toHaveFocus();
    expect(detailsHeading.closest('section')).toHaveTextContent('Packet 2');
  });

  it('shows a typed parser error in an alert and disposes on teardown', async () => {
    const error = {
      code: 'TRUNCATED_GLOBAL_HEADER',
      message: 'Capture header is truncated',
      captureOffset: 0,
      packetNumber: null,
    };
    const view = render(Page);
    instances[0].parse.mockRejectedValue(error);
    await fireEvent.change(screen.getByLabelText(/capture file/i), {
      target: { files: [capture('broken.pcap')] },
    });
    expect(await screen.findByRole('alert')).toHaveTextContent(/capture header is truncated/i);
    view.unmount();
    expect(instances[0].dispose).toHaveBeenCalledTimes(1);
  });

  it('keeps the selected conversation when a packet is selected', async () => {
    const secondFlowDocument = {
      ...demoDocument,
      endpoints: [
        ...demoDocument.endpoints,
        {
          id: 'endpoint-other-client',
          address: '203.0.113.10',
          port: 40000,
          addressFamily: 'ipv4' as const,
        },
        {
          id: 'endpoint-other-server',
          address: '203.0.113.20',
          port: 8443,
          addressFamily: 'ipv4' as const,
        },
      ],
      flows: [
        ...demoDocument.flows,
        {
          id: 'tcp-flow-2',
          protocol: 'TCP' as const,
          clientEndpointId: 'endpoint-other-client',
          serverEndpointId: 'endpoint-other-server',
          startTimestampNs: '1000000000',
          endTimestampNs: '1020000000',
          packetNumbers: [1],
          capturedBytes: 54,
          originalBytes: 54,
          handshake: 'partial' as const,
          midStream: true,
          termination: 'unknown' as const,
          events: [],
        },
      ],
    };
    render(Page);
    instances[0].parse.mockResolvedValue(secondFlowDocument);
    await fireEvent.change(screen.getByLabelText(/capture file/i), {
      target: { files: [capture()] },
    });
    const secondFlow = await screen.findByRole('button', {
      name: /203\.0\.113\.10.*203\.0\.113\.20/i,
    });
    await secondFlow.click();
    expect(secondFlow).toHaveAttribute('aria-pressed', 'true');
    await screen.getByRole('button', { name: /packet 1/i }).click();
    expect(secondFlow).toHaveAttribute('aria-pressed', 'true');
  });
});
