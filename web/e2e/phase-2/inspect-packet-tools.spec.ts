import { expect, test } from '@playwright/test';
import { dnsFixturePath } from '../fixtures';

test('filters and searches DNS evidence, highlights exact bytes, and follows an observation', async ({
  page,
}, testInfo) => {
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
  await page.getByLabel('Capture file').setInputFiles(dnsFixturePath);

  const filter = page.getByLabel('Packet filter');
  const search = page.getByLabel('Search packet facts');
  await expect(page.getByText('Showing all 14 packets.')).toBeVisible();

  await filter.fill('tcp');
  await expect(page.getByText('No packets match the current filter and search.')).toBeVisible();
  await filter.fill('DnS');
  await expect(page.getByText('Showing all 14 packets.')).toBeVisible();

  await filter.fill('dns icmp');
  await expect(page.getByRole('alert')).toContainText('Unsupported filter term: icmp');
  await expect(page.getByText('Showing all 14 packets.')).toBeVisible();

  await search.fill('2001:db8::35');
  await expect(page.getByText('Showing 1 of 14 packets.')).toBeVisible();
  await expect(page.getByRole('button', { name: /^Packet 4:/ })).toBeVisible();
  await expect(page.getByRole('button', { name: /^Packet 1:/ })).toHaveCount(0);

  await filter.fill('dns');
  await search.fill('');
  await page.getByRole('button', { name: /^Packet 1:/ }).click();
  await expect(page.getByText('71 bytes')).toBeVisible();
  await page.getByRole('button', { name: 'Show questionName field bytes' }).click();
  const selectedBytes = page.locator('mark[data-offset]');
  await expect(selectedBytes).toHaveCount(13);
  await expect(selectedBytes.first()).toHaveAttribute('data-offset', '54');
  await expect(selectedBytes.last()).toHaveAttribute('data-offset', '66');
  await expect(page.getByText('Selected field: bytes 54–66.')).toBeVisible();
  await page.screenshot({
    path: testInfo.outputPath('inspection-tools-highlight.png'),
    fullPage: true,
  });

  await page
    .getByRole('button', {
      name: 'View evidence packet 10 for DNS response latency met the slow-response rule',
    })
    .click();
  await expect(page.getByRole('heading', { name: 'Packet details' })).toBeFocused();
  await expect(
    page.getByRole('region', { name: 'Packet details' }).getByText('Packet 10', { exact: true }),
  ).toBeVisible();
  await expect(filter).toHaveValue('');
  await expect(search).toHaveValue('');

  expect(consoleErrors).toEqual([]);
  expect(pageErrors).toEqual([]);
  expect(externalRequests).toEqual([]);

  await page.screenshot({
    path: testInfo.outputPath('inspection-tools-evidence.png'),
    fullPage: true,
  });
});
