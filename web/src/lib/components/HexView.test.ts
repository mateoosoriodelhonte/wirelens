import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import HexView from './HexView.svelte';

function bytes(values: number[]): Uint8Array {
  return new Uint8Array(values);
}

describe('HexView', () => {
  it('explains that no packet is selected when no bytes are provided', () => {
    render(HexView);

    expect(screen.getByRole('status')).toHaveTextContent(/select a packet/i);
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('shows an empty state for a selected packet with no captured bytes', () => {
    render(HexView, { props: { bytes: new Uint8Array() } });

    expect(screen.getByRole('status')).toHaveTextContent(/no packet bytes/i);
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('shows loading and byte-retrieval failure states', () => {
    const loading = render(HexView, { props: { loading: true } });
    expect(screen.getByRole('status')).toHaveTextContent(/loading selected packet bytes/i);
    loading.unmount();

    render(HexView, { props: { error: 'Packet bytes are not available.' } });
    expect(screen.getByRole('alert')).toHaveTextContent(/packet bytes are not available/i);
  });

  it('renders 16-byte rows with offsets and a printable ASCII alternative', () => {
    const packetBytes = bytes([
      0x00, 0x20, 0x41, 0x7e, 0x7f, 0xff, 0x42, 0x0a, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49,
      0x4a, 0x4b,
    ]);
    render(HexView, { props: { bytes: packetBytes } });

    const table = screen.getByRole('table', { name: /selected packet bytes/i });
    expect(table).toBeInTheDocument();
    expect(screen.getAllByRole('row')).toHaveLength(3);
    expect(screen.getByText('00000000')).toBeInTheDocument();
    const firstDataRow = screen.getAllByRole('row')[1];
    expect(firstDataRow.querySelector('.hex-bytes')).toHaveTextContent(
      '00 20 41 7e 7f ff 42 0a 43 44 45 46 47 48 49 4a',
    );
    expect(firstDataRow.querySelector('.ascii')).toHaveTextContent('. A~..B.CDEFGHIJ');
    expect(screen.getAllByRole('row')[2].querySelector('.hex-bytes')).toHaveTextContent('4b');
  });

  it('highlights exactly the requested field range, including the last byte', () => {
    const packetBytes = bytes(Array.from({ length: 16 }, (_, index) => index));
    render(HexView, {
      props: { bytes: packetBytes, fieldRange: { captureOffset: 0, packetOffset: 13, length: 3 } },
    });

    const selected = screen.getAllByRole('mark');
    expect(selected).toHaveLength(3);
    expect(selected.map((element) => element.getAttribute('data-offset'))).toEqual([
      '13',
      '14',
      '15',
    ]);
    expect(selected.map((element) => element.textContent)).toEqual(['0d', '0e', '0f']);
    expect(screen.getByText(/selected field: bytes 13–15/i)).toBeInTheDocument();
  });

  it('does not highlight a zero-length or invalid overflowing field range', () => {
    const packetBytes = bytes(Array.from({ length: 16 }, (_, index) => index));
    const view = render(HexView, {
      props: { bytes: packetBytes, fieldRange: { captureOffset: 0, packetOffset: 16, length: 0 } },
    });
    expect(screen.queryAllByRole('mark')).toHaveLength(0);
    expect(screen.getByRole('status')).toHaveTextContent(/field range.*not available/i);
    view.unmount();

    render(HexView, {
      props: {
        bytes: packetBytes,
        fieldRange: {
          captureOffset: 0,
          packetOffset: Number.MAX_SAFE_INTEGER,
          length: Number.MAX_SAFE_INTEGER,
        },
      },
    });
    expect(screen.queryAllByRole('mark')).toHaveLength(0);
    expect(screen.getByRole('status')).toHaveTextContent(/outside packet bytes/i);
  });

  it('keeps bytes as text and provides keyboard-visible row focus without per-byte tab stops', () => {
    render(HexView, {
      props: { bytes: bytes([0x3c, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x3e]) },
    });

    const row = screen.getByRole('row', { name: /offset 0/i });
    expect(row).toHaveAttribute('tabindex', '0');
    expect(row).toHaveAttribute('aria-label', expect.stringMatching(/offset 0/i));
    expect(screen.queryAllByRole('button')).toHaveLength(0);
    expect(screen.queryByText('<script>')).not.toBeInTheDocument();
    expect(row.querySelector('.hex-bytes')).toHaveTextContent('3c 73 63 72 69 70 74 3e');
  });
});
