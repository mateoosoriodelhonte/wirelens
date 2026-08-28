import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import PacketTable from './PacketTable.svelte';
import { demoDocument } from '../demo-document';

describe('PacketTable', () => {
  it('selects packet rows with buttons and aria-current', async () => {
    const selected = { value: '' };
    const view = render(PacketTable, {
      props: {
        document: demoDocument,
        selectedPacketId: '',
        onSelect: (id: string) => (selected.value = id),
      },
    });
    const packet = screen.getByRole('button', { name: /packet 1/i });
    await packet.click();
    expect(selected.value).toBe('packet-1');
    await view.rerender({
      document: demoDocument,
      selectedPacketId: 'packet-1',
      onSelect: (id: string) => (selected.value = id),
    });
    expect(packet).toHaveAttribute('aria-current', 'true');
    await view.rerender({
      document: demoDocument,
      selectedPacketId: '',
      onSelect: (id: string) => (selected.value = id),
    });
    expect(packet).not.toHaveAttribute('aria-current', 'true');
    expect(screen.getByRole('columnheader', { name: /protocol/i })).toBeInTheDocument();
  });

  it('renders only the filtered packet result set', () => {
    render(PacketTable, {
      props: {
        document: demoDocument,
        packets: [demoDocument.packets[1]],
        onSelect: () => undefined,
      },
    });
    expect(screen.getByRole('button', { name: /packet 2/i })).toBeVisible();
    expect(screen.queryByRole('button', { name: /packet 1/i })).not.toBeInTheDocument();
    expect(screen.getByText('1', { selector: '.count' })).toBeVisible();
  });
});
