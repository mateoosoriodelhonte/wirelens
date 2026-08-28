import { expect, test } from '@playwright/test';
import { httpFixturePath, tlsFixturePath } from '../fixtures';

test('shows sanitized HTTP and bounded TLS handshake evidence', async ({ page }, testInfo) => {
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
  const input = page.getByLabel('Capture file');
  await input.setInputFiles(httpFixturePath);

  const http = page.getByRole('region', { name: 'HTTP exchanges' });
  await expect(http).toBeVisible();
  await expect(http.getByText('Matched', { exact: true })).toBeVisible();
  await expect(
    http.getByText('POST /search?term=[redacted]&sort=[redacted] HTTP/1.1', { exact: true }),
  ).toBeVisible();
  await expect(http.getByText('HTTP/1.1 200 OK', { exact: true })).toBeVisible();
  await expect(http.getByText('example.test', { exact: true })).toBeVisible();
  await expect(http.getByText('authorization', { exact: true })).toBeVisible();
  await expect(http.getByText('cookie', { exact: true })).toBeVisible();
  await expect(http.getByText('x-api-key', { exact: true })).toBeVisible();
  await expect(http.getByText('[redacted]', { exact: true })).toHaveCount(3);
  await expect(page.locator('body')).not.toContainText('wirelens-http-header-secret-29');
  await expect(page.locator('body')).not.toContainText('wirelens-http-body-secret-29');

  const requestEvidence = http.getByRole('button', { name: 'View HTTP request packet 5' });
  await requestEvidence.focus();
  await expect(requestEvidence).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.getByRole('heading', { name: 'Packet details' })).toBeFocused();
  await expect(page.getByText('Packet 5', { exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'HTTP', exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('http-redaction.png'), fullPage: true });

  await input.setInputFiles(tlsFixturePath);
  const tls = page.getByRole('region', { name: 'TLS handshakes' });
  await expect(tls).toBeVisible();
  await expect(tls.getByText('Matched', { exact: true })).toBeVisible();
  await expect(tls.getByRole('heading', { name: 'ClientHello', exact: true })).toBeVisible();
  await expect(tls.getByRole('heading', { name: 'ServerHello', exact: true })).toBeVisible();
  await expect(tls.getByText('example.test', { exact: true })).toBeVisible();
  await expect(tls.getByText('TLS 1.3, TLS 1.2', { exact: true })).toBeVisible();
  await expect(tls.getByText('TLS 1.3', { exact: true })).toBeVisible();
  await expect(
    tls.getByText('WireLens does not decrypt TLS application data.', { exact: true }),
  ).toBeVisible();

  await tls.getByRole('button', { name: 'View TLS ServerHello packet 5' }).click();
  await expect(page.getByRole('heading', { name: 'Packet details' })).toBeFocused();
  await expect(page.getByText('Packet 5', { exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'TLS', exact: true })).toBeVisible();

  expect(consoleErrors).toEqual([]);
  expect(pageErrors).toEqual([]);
  expect(externalRequests).toEqual([]);

  await page.screenshot({ path: testInfo.outputPath('tls-handshake.png'), fullPage: true });
});
