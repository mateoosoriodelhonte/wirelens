import { expect, test } from '@playwright/test';
import { tcpResetFixturePath, tcpRetransmissionFixturePath } from '../fixtures';

function channel(value: number): number {
  const normalized = value / 255;
  return normalized <= 0.04045 ? normalized / 12.92 : Math.pow((normalized + 0.055) / 1.055, 2.4);
}

function luminance(color: string): number {
  const values = color
    .match(/[\d.]+/g)
    ?.slice(0, 3)
    .map(Number);
  if (!values || values.length !== 3) throw new Error(`Unsupported computed color: ${color}`);
  return 0.2126 * channel(values[0]) + 0.7152 * channel(values[1]) + 0.0722 * channel(values[2]);
}

function contrast(foreground: string, background: string): number {
  const [lighter, darker] = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
  return (lighter + 0.05) / (darker + 0.05);
}

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
  const resetEvidence = observations.getByRole('button', {
    name: 'View evidence packet 4 for TCP reset was observed.',
  });
  await resetEvidence.focus();
  await expect(resetEvidence).toBeFocused();
  const colors = await resetEvidence.evaluate((element) => {
    const style = getComputedStyle(element);
    return { foreground: style.color, background: style.backgroundColor };
  });
  expect(contrast(colors.foreground, colors.background)).toBeGreaterThanOrEqual(4.5);
  await page.keyboard.press('Enter');
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
