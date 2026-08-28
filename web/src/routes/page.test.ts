import { fireEvent, render, screen, waitFor } from '@testing-library/svelte';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { demoDocument } from '$lib/demo-document';

const { instances, MockParser } = vi.hoisted(() => {
  const created: Array<{
    parse: ReturnType<typeof vi.fn>;
    getPacketBytes: ReturnType<typeof vi.fn>;
    dispose: ReturnType<typeof vi.fn>;
  }> = [];
  class Parser {
    readonly parse = vi.fn();
    readonly getPacketBytes = vi.fn(async () => new Uint8Array(54).buffer);
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
    expect(screen.getByRole('heading', { name: /http exchanges/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /tls handshakes/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Observations' })).toBeInTheDocument();
    expect(screen.getByText('SYN + ACK')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /ethernet/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /ipv4/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /tcp/i })).toBeInTheDocument();
    expect(screen.getByRole('main')).not.toHaveAttribute('aria-busy', 'true');
  });

  it('renders HTTP and TLS metadata and follows their packet evidence', async () => {
    const applicationDocument = {
      ...demoDocument,
      httpExchanges: [
        {
          id: 'http-exchange-1',
          flowId: 'tcp-flow-1',
          request: {
            line: 'GET / HTTP/1.1',
            method: 'GET',
            target: '/',
            version: 'HTTP/1.1' as const,
            headers: [{ name: 'host', value: 'example.test', redacted: false }],
            packetNumbers: [1],
          },
          response: null,
          latencyNs: null,
          matched: false,
        },
      ],
      tlsHandshakes: [
        {
          id: 'tls-handshake-1',
          flowId: 'tcp-flow-1',
          clientHello: {
            recordVersion: 'TLS 1.0',
            legacyVersion: 'TLS 1.2',
            offeredVersions: ['TLS 1.3'],
            serverName: null,
            packetNumbers: [2],
          },
          serverHello: null,
          matched: false,
          limitation: 'WireLens does not decrypt TLS application data.',
        },
      ],
    };
    render(Page);
    instances[0].parse.mockResolvedValue(applicationDocument);
    await fireEvent.change(screen.getByLabelText(/capture file/i), {
      target: { files: [capture('application.pcap')] },
    });
    expect(await screen.findByText('GET / HTTP/1.1')).toBeVisible();
    expect(screen.getByText('WireLens does not decrypt TLS application data.')).toBeVisible();
    await fireEvent.click(screen.getByRole('button', { name: 'View TLS ClientHello packet 2' }));
    expect(screen.getByRole('heading', { name: 'Packet details' })).toHaveFocus();
    expect(
      screen.getByRole('heading', { name: 'Packet details' }).closest('section'),
    ).toHaveTextContent('Packet 2');
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

  it('applies AND filters and preserves the last valid packet set on invalid input', async () => {
    const filterDocument = structuredClone(demoDocument);
    filterDocument.packets[1].layers.push({
      protocol: 'DNS',
      label: 'DNS response',
      fields: [],
      byteRange: null,
      explanationKey: 'dns',
    });
    render(Page);
    instances[0].parse.mockResolvedValue(filterDocument);
    await fireEvent.change(screen.getByLabelText(/capture file/i), {
      target: { files: [capture('filter.pcap')] },
    });

    const filter = await screen.findByLabelText(/packet filter/i);
    await fireEvent.input(filter, { target: { value: 'DnS port:443' } });
    expect(screen.getByText('Showing 1 of 3 packets.')).toBeVisible();
    expect(screen.getByRole('button', { name: /packet 2:/i })).toBeVisible();
    expect(screen.queryByRole('button', { name: /packet 1:/i })).not.toBeInTheDocument();

    await fireEvent.input(filter, { target: { value: 'dns icmp' } });
    expect(screen.getByRole('alert')).toHaveTextContent(/unsupported filter term: icmp/i);
    expect(screen.getByText('Showing 1 of 3 packets.')).toBeVisible();
    expect(screen.getByRole('button', { name: /packet 2:/i })).toBeVisible();
  });

  it('searches approved normalized facts and never raw or query values', async () => {
    const searchDocument = structuredClone(demoDocument);
    searchDocument.packets[1].layers.push({
      protocol: 'HTTP',
      label: 'HTTP request',
      fields: [],
      byteRange: null,
      explanationKey: 'http',
    });
    searchDocument.httpExchanges = [
      {
        id: 'http-exchange-1',
        flowId: 'tcp-flow-1',
        request: {
          line: 'GET /safe?token=QUERY_SECRET_SENTINEL HTTP/1.1',
          method: 'GET',
          target: '/safe?token=QUERY_SECRET_SENTINEL',
          version: 'HTTP/1.1',
          headers: [{ name: 'host', value: 'search.example.test', redacted: false }],
          packetNumbers: [2],
        },
        response: null,
        latencyNs: null,
        matched: false,
      },
    ];
    render(Page);
    instances[0].parse.mockResolvedValue(searchDocument);
    await fireEvent.change(screen.getByLabelText(/capture file/i), {
      target: { files: [capture('search.pcap')] },
    });

    const search = await screen.findByLabelText(/search packet facts/i);
    await fireEvent.input(search, { target: { value: 'HTTP search.example.test safe' } });
    expect(screen.getByText('Showing 1 of 3 packets.')).toBeVisible();
    expect(screen.getByRole('button', { name: /packet 2:/i })).toBeVisible();

    await fireEvent.input(search, { target: { value: 'QUERY_SECRET_SENTINEL' } });
    expect(screen.getByText(/no packets match/i)).toBeVisible();
    expect(screen.queryByRole('button', { name: /packet 2:/i })).not.toBeInTheDocument();
  });

  it('loads one selected packet buffer and highlights the exact selected field bytes', async () => {
    const rangedDocument = structuredClone(demoDocument);
    const tcp = rangedDocument.packets[0].layers.find((layer) => layer.protocol === 'TCP');
    if (!tcp) throw new Error('TCP fixture is missing');
    tcp.fields[0].byteRange = { captureOffset: 46, packetOffset: 12, length: 2 };
    const packetBytes = new Uint8Array(Array.from({ length: 54 }, (_, index) => index)).buffer;
    render(Page);
    instances[0].parse.mockResolvedValue(rangedDocument);
    instances[0].getPacketBytes.mockResolvedValue(packetBytes);
    await fireEvent.change(screen.getByLabelText(/capture file/i), {
      target: { files: [capture('bytes.pcap')] },
    });

    expect(await screen.findByText('54 bytes')).toBeVisible();
    expect(instances[0].getPacketBytes).toHaveBeenCalledWith(0);
    await fireEvent.click(screen.getByRole('button', { name: /show Flags field bytes/i }));
    const selected = screen.getAllByRole('mark');
    expect(selected).toHaveLength(2);
    expect(selected.map((element) => element.getAttribute('data-offset'))).toEqual(['12', '13']);
  });

  it('shows selected packet byte failures without dropping normalized packet details', async () => {
    render(Page);
    instances[0].parse.mockResolvedValue(demoDocument);
    instances[0].getPacketBytes.mockRejectedValue({
      code: 'TRUNCATED_PACKET_DATA',
      message: 'Selected packet bytes are unavailable',
      captureOffset: null,
      packetNumber: 1,
    });
    await fireEvent.change(screen.getByLabelText(/capture file/i), {
      target: { files: [capture('bytes-error.pcap')] },
    });

    expect(await screen.findByRole('alert')).toHaveTextContent(
      /selected packet bytes are unavailable/i,
    );
    expect(screen.getByRole('heading', { name: 'Packet details' })).toBeVisible();
  });
});
