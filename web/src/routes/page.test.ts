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
    expect(screen.queryByText(/pcapng/i)).not.toBeInTheDocument();
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
    expect(screen.getByText('SYN + ACK')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /ethernet/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /ipv4/i })).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /tcp/i })).toBeInTheDocument();
    expect(screen.getByRole('main')).not.toHaveAttribute('aria-busy', 'true');
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
});
