import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import TcpSequence from './TcpSequence.svelte';
import { demoDocument } from '../demo-document';

describe('TcpSequence', () => {
  it('labels all handshake events without using color alone', () => {
    render(TcpSequence, { props: { document: demoDocument, flow: demoDocument.flows[0] } });
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
          ...demoDocument.flows[0],
          packetNumbers: [7],
          events: [{ ...demoDocument.flows[0].events[0], packetNumber: 7 }],
        },
      ],
    };
    render(TcpSequence, { props: { document, flow: document.flows[0] } });
    expect(screen.getByRole('rowheader', { name: '7' })).toBeInTheDocument();
  });
});
