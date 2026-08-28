import { expect, test } from '@playwright/test';
import { ipv6UdpPcapngFixturePath } from '../fixtures';

test('inspects PCAPNG IPv6 and UDP evidence through the browser worker', async ({ page }) => {
  const consoleErrors: string[] = [];
  const pageErrors: string[] = [];
  const externalRequests: string[] = [];

  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('pageerror', (error) => pageErrors.push(error.message));
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (
      (url.protocol === 'http:' || url.protocol === 'https:') &&
      url.hostname !== '127.0.0.1' &&
      url.hostname !== 'localhost'
    ) {
      externalRequests.push(request.url());
    }
  });

  await page.goto('/');
  await page.getByLabel('Capture file').setInputFiles(ipv6UdpPcapngFixturePath);

  const overview = page.getByRole('region', { name: 'Capture overview' });
  await expect(overview).toBeVisible();
  await expect(overview.getByText('PCAPNG', { exact: true })).toBeVisible();
  await expect(overview.getByText('1 packets', { exact: true })).toBeVisible();

  const flow = page.getByRole('button', { name: /2001:db8::1:53000.*2001:db8::2:53/ });
  await expect(flow).toContainText('UDP datagrams');
  await flow.click();
  await expect(page.getByRole('region', { name: 'UDP flow' })).toContainText(
    'This flow has no TCP sequence handshake.',
  );

  await page.getByRole('button', { name: 'Packet 1: UDP datagram' }).click();
  const details = page.getByRole('region', { name: 'Packet details' });
  await expect(details.getByRole('heading', { name: 'IPV6', exact: true })).toBeVisible();
  await expect(details.getByRole('heading', { name: 'UDP', exact: true })).toBeVisible();
  await expect(details.getByText('2001:db8::1', { exact: true })).toBeVisible();
  await expect(details.getByText('2001:db8::2', { exact: true })).toBeVisible();
  await expect(details.getByText('53000', { exact: true })).toBeVisible();
  await expect(details.getByText('53', { exact: true })).toBeVisible();

  expect(consoleErrors).toEqual([]);
  expect(pageErrors).toEqual([]);
  expect(externalRequests).toEqual([]);
});
