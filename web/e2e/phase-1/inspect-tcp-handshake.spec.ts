import { expect, test } from '@playwright/test';
import { handshakeFixturePath, readyCaptureInput } from '../fixtures';

test('inspects the synthetic TCP handshake from file selection to packet details', async ({
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
  await expect(
    page.getByRole('heading', { name: 'Inspect a capture on this device' }),
  ).toBeVisible();

  await (await readyCaptureInput(page)).setInputFiles(handshakeFixturePath);
  await expect(page.getByRole('heading', { name: 'Capture overview' })).toBeVisible();
  await expect(page.getByText('3 packets', { exact: true })).toBeVisible();
  await expect(
    page.getByRole('list', { name: 'Capture metrics' }).getByText('TCP flow', { exact: true }),
  ).toBeVisible();

  const flow = page.getByRole('button', {
    name: /192\.0\.2\.10:51515.*198\.51\.100\.20:443/,
  });
  await expect(flow).toBeVisible();
  await expect(flow).toContainText('Handshake complete');
  await flow.click();

  const sequence = page.getByRole('table', { name: 'Text alternative for TCP sequence' });
  await expect(
    sequence.getByRole('row', { name: /SYN.*client asks to start a TCP connection/ }),
  ).toBeVisible();
  await expect(
    sequence.getByRole('row', { name: /SYN \+ ACK.*server accepts and acknowledges/ }),
  ).toBeVisible();
  await expect(
    sequence.getByRole('row', { name: /ACK.*client acknowledges the server/ }),
  ).toBeVisible();

  await page.getByRole('button', { name: /Packet 1:/ }).click();
  await expect(page.getByRole('heading', { name: 'Packet details' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'ETHERNET', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'IPV4', exact: true })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'TCP', exact: true })).toBeVisible();
  await expect(
    page.getByText(/Synchronize sequence numbers to\s+begin a connection\./),
  ).toBeVisible();

  expect(consoleErrors).toEqual([]);
  expect(pageErrors).toEqual([]);
  expect(externalRequests).toEqual([]);

  await page.screenshot({ path: testInfo.outputPath('handshake-overview.png'), fullPage: false });
});
