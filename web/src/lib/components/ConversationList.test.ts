import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import ConversationList from './ConversationList.svelte';
import { demoDocument } from '../demo-document';

describe('ConversationList', () => {
  it('renders keyboard-selectable TCP conversations', async () => {
    const selected = { value: '' };
    const view = render(ConversationList, {
      props: {
        flows: demoDocument.flows,
        endpoints: demoDocument.endpoints,
        selectedFlowId: '',
        onSelect: (id: string) => (selected.value = id),
      },
    });
    const row = screen.getByRole('button', { name: /192\.0\.2\.10.*198\.51\.100\.20/i });
    expect(row).toBeVisible();
    expect(row).toHaveAttribute('aria-pressed', 'false');
    await row.focus();
    expect(document.activeElement).toBe(row);
    await row.click();
    expect(selected.value).toBe('tcp-flow-1');
    await view.rerender({
      flows: demoDocument.flows,
      endpoints: demoDocument.endpoints,
      selectedFlowId: 'tcp-flow-1',
      onSelect: (id: string) => (selected.value = id),
    });
    expect(row).toHaveAttribute('aria-pressed', 'true');
    await view.rerender({
      flows: demoDocument.flows,
      endpoints: demoDocument.endpoints,
      selectedFlowId: '',
      onSelect: (id: string) => (selected.value = id),
    });
    expect(row).toHaveAttribute('aria-pressed', 'false');
  });
});
