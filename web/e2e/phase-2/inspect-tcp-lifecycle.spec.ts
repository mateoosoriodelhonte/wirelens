import { expect, test } from '@playwright/test';
import { tcpResetFixturePath, tcpRetransmissionFixturePath } from '../fixtures';

test('inspects TCP reset and conservative retransmission evidence', async ({ page }, testInfo) => {
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
  await input.setInputFiles(tcpResetFixturePath);

  const observations = page.getByRole('region', { name: 'Observations' });
  const sequence = page.getByRole('region', { name: 'Connection sequence' });
  await expect(observations.getByText('TCP reset was observed.')).toBeVisible();
  await expect(sequence.getByText('Reset observed')).toBeVisible();
  await expect(sequence.getByText('RST', { exact: true })).toBeVisible();
  await observations
    .getByRole('button', { name: 'View evidence packet 4 for TCP reset was observed.' })
    .click();
  await expect(page.getByRole('heading', { name: 'Packet details' })).toBeFocused();

  await input.setInputFiles(tcpRetransmissionFixturePath);
  await expect(
    observations.getByText('TCP segment appears to resend bytes already seen.'),
  ).toBeVisible();
  await expect(sequence.getByText('Graceful close')).toBeVisible();
  await expect(sequence.getByText('DATA', { exact: true }).first()).toBeVisible();
  await expect(sequence.getByText('FIN + ACK', { exact: true }).first()).toBeVisible();
  await observations
    .getByRole('button', {
      name: 'View evidence packet 5 for TCP segment appears to resend bytes already seen.',
    })
    .click();
  await expect(page.getByRole('heading', { name: 'Packet details' })).toBeFocused();

  expect(consoleErrors).toEqual([]);
  expect(pageErrors).toEqual([]);
  expect(externalRequests).toEqual([]);

  await page.screenshot({ path: testInfo.outputPath('tcp-lifecycle.png'), fullPage: true });
});
