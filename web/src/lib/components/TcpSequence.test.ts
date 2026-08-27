import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import TcpSequence from './TcpSequence.svelte';
import { demoDocument } from '../demo-document';
import type { TcpFlow } from '../model';

const tcpFlow = demoDocument.flows.find((flow): flow is TcpFlow => flow.protocol === 'TCP')!;

describe('TcpSequence', () => {
  it('labels all handshake events without using color alone', () => {
    render(TcpSequence, { props: { document: demoDocument, flow: tcpFlow } });
    expect(screen.getByText('SYN')).toBeInTheDocument();
    expect(screen.getByText('SYN + ACK')).toBeInTheDocument();
    expect(screen.getByText('ACK')).toBeInTheDocument();
    expect(screen.getByRole('table')).toHaveAccessibleName(/text alternative/i);
  });

  it('uses capture packet numbers in the text alternative', () => {
    const document = {
      ...demoDocument,
      packets: [{ ...demoDocument.packets[0], number: 7 }],
      flows: [
        {
          ...tcpFlow,
          packetNumbers: [7],
          events: [{ ...tcpFlow.events[0], packetNumber: 7 }],
        },
      ],
    };
    render(TcpSequence, { props: { document, flow: document.flows[0] as TcpFlow } });
    expect(screen.getByRole('rowheader', { name: '7' })).toBeInTheDocument();
  });

  it('shows lifecycle state, mid-stream limits, and close events in text', () => {
    const flow: TcpFlow = {
      ...tcpFlow,
      midStream: true,
      termination: 'reset',
      packetNumbers: [1],
      events: [{ packetNumber: 1, label: 'RST' }],
    };
    render(TcpSequence, { props: { document: demoDocument, flow } });
    expect(screen.getByText('Reset observed')).toBeVisible();
    expect(screen.getByText(/initial SYN was not observed/i)).toBeVisible();
    expect(screen.getByText(/stops the TCP connection immediately/i)).toBeVisible();
  });
});
