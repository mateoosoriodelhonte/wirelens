import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it, vi } from 'vitest';
import CapturePicker from './CapturePicker.svelte';

describe('CapturePicker', () => {
  it('accepts PCAP files and reports them to the caller', async () => {
    const onFile = vi.fn();
    render(CapturePicker, { props: { onFile } });
    const input = screen.getByLabelText(/capture file/i);
    const file = new File(['pcap'], 'handshake.pcap', { type: 'application/vnd.tcpdump.pcap' });
    await fireEvent.change(input, { target: { files: [file] } });
    expect(onFile).toHaveBeenCalledWith(file);
    expect(screen.getByRole('status')).toHaveTextContent(/ready to inspect/i);
  });

  it('accepts PCAPNG files and reports them to the caller', async () => {
    const onFile = vi.fn();
    render(CapturePicker, { props: { onFile } });
    const file = new File(['pcapng'], 'capture.pcapng', { type: 'application/vnd.tcpdump.pcapng' });
    await fireEvent.change(screen.getByLabelText(/capture file/i), { target: { files: [file] } });
    expect(onFile).toHaveBeenCalledWith(file);
  });

  it('rejects unsupported extensions before parsing', async () => {
    const onFile = vi.fn();
    render(CapturePicker, { props: { onFile } });
    const input = screen.getByLabelText(/capture file/i);
    await fireEvent.change(input, { target: { files: [new File(['x'], 'notes.txt')] } });
    expect(onFile).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toHaveTextContent(/\.pcap/i);
  });
});
