import { fireEvent, render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import type { HttpExchange } from '../model';
import HttpExchangeList from './HttpExchangeList.svelte';

const exchanges: HttpExchange[] = [
  {
    id: 'http-exchange-1',
    flowId: 'tcp-flow-1',
    request: {
      line: 'GET /search?q=[redacted] HTTP/1.1',
      method: 'GET',
      target: '/search?q=[redacted]',
      version: 'HTTP/1.1',
      headers: [
        { name: 'host', value: 'example.test', redacted: false },
        { name: 'authorization', value: null, redacted: true },
      ],
      packetNumbers: [4],
    },
    response: {
      line: 'HTTP/1.1 200 OK',
      version: 'HTTP/1.1',
      statusCode: 200,
      reason: 'OK',
      headers: [{ name: 'server', value: 'wirelens-test', redacted: false }],
      packetNumbers: [5],
    },
    latencyNs: '12500000',
    matched: true,
  },
  {
    id: 'http-exchange-2',
    flowId: 'tcp-flow-1',
    request: {
      line: 'POST /submit HTTP/1.1',
      method: 'POST',
      target: '/submit',
      version: 'HTTP/1.1',
      headers: [],
      packetNumbers: [6],
    },
    response: null,
    latencyNs: null,
    matched: false,
  },
];

describe('HttpExchangeList', () => {
  it('renders the empty state', () => {
    render(HttpExchangeList, { props: { exchanges: [], onSelectPacket: () => {} } });
    expect(screen.getByRole('heading', { name: 'HTTP exchanges' })).toBeVisible();
    expect(screen.getByText(/no HTTP exchanges were found/i)).toBeVisible();
  });

  it('renders matched and unmatched lines, selected headers, redaction, and latency', () => {
    render(HttpExchangeList, { props: { exchanges, onSelectPacket: () => {} } });
    expect(screen.getByText('Matched')).toBeVisible();
    expect(screen.getByText('Unmatched')).toBeVisible();
    expect(screen.getByText('GET /search?q=[redacted] HTTP/1.1')).toBeVisible();
    expect(screen.getByText('HTTP/1.1 200 OK')).toBeVisible();
    expect(screen.getByText('example.test')).toBeVisible();
    expect(screen.getByText('[redacted]')).toBeVisible();
    expect(screen.getByText('12.5 ms')).toBeVisible();
    expect(screen.getByText(/no matching response/i)).toBeVisible();
  });

  it('provides keyboard-focusable packet evidence buttons', async () => {
    let selected = 0;
    render(HttpExchangeList, {
      props: { exchanges, onSelectPacket: (number) => (selected = number) },
    });
    const request = screen.getByRole('button', { name: 'View HTTP request packet 4' });
    request.focus();
    expect(request).toHaveFocus();
    await fireEvent.click(request);
    expect(selected).toBe(4);
    await fireEvent.click(screen.getByRole('button', { name: 'View HTTP response packet 5' }));
    expect(selected).toBe(5);
  });

  it('does not render a redacted secret value', () => {
    render(HttpExchangeList, { props: { exchanges, onSelectPacket: () => {} } });
    expect(screen.queryByText('Bearer hidden-secret')).not.toBeInTheDocument();
  });

  it('renders repeated header names without a duplicate-key failure', () => {
    const repeatedHeaders: HttpExchange = {
      ...exchanges[0],
      request: {
        ...exchanges[0].request!,
        headers: [
          { name: 'accept', value: 'text/plain', redacted: false },
          { name: 'accept', value: 'application/json', redacted: false },
        ],
      },
      response: {
        ...exchanges[0].response!,
        headers: [
          { name: 'server', value: 'first', redacted: false },
          { name: 'server', value: 'second', redacted: false },
        ],
      },
    };
    render(HttpExchangeList, { props: { exchanges: [repeatedHeaders], onSelectPacket: () => {} } });
    expect(screen.getAllByText('accept')).toHaveLength(2);
    expect(screen.getByText('text/plain')).toBeVisible();
    expect(screen.getByText('application/json')).toBeVisible();
    expect(screen.getAllByText('server')).toHaveLength(2);
    expect(screen.getByText('first')).toBeVisible();
    expect(screen.getByText('second')).toBeVisible();
  });
});
