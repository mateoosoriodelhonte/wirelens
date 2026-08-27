import { expect, test } from '@playwright/test';
import { dnsFixturePath } from '../fixtures';

test('inspects synthetic DNS exchanges and follows packet evidence', async ({ page }, testInfo) => {
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
  await expect(
    page.getByText('.pcap · .pcapng · up to 64 MiB · drag and drop also works'),
  ).toBeVisible();
  await page.getByLabel('Capture file').setInputFiles(dnsFixturePath);

  const dns = page.getByRole('region', { name: 'DNS exchanges' });
  await expect(dns).toBeVisible();
  await expect(dns.getByRole('heading', { name: 'example.com' }).first()).toBeVisible();
  await expect(dns.getByText('192.0.2.53').first()).toBeVisible();
  await expect(dns.getByText('2001:db8::35')).toBeVisible();
  await expect(dns.getByText('NXDOMAIN', { exact: true })).toBeVisible();
  await expect(dns.getByText('SERVFAIL', { exact: true })).toBeVisible();
  await expect(dns.getByText('DNS response latency met the slow-response rule')).toBeVisible();

  await dns.getByRole('button', { name: 'View response packet 2 for example.com' }).click();
  await expect(page.getByRole('heading', { name: 'Packet details' })).toBeFocused();
  await expect(page.getByText('Packet 2', { exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'DNS', exact: true })).toBeVisible();

  expect(consoleErrors).toEqual([]);
  expect(pageErrors).toEqual([]);
  expect(externalRequests).toEqual([]);

  await page.screenshot({ path: testInfo.outputPath('dns-exchanges.png'), fullPage: true });
});
