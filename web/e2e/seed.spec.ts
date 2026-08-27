import { expect, test } from '@playwright/test';

test('starts in the local-only empty state', async ({ page }) => {
  const externalRequests: string[] = [];
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
  await expect(page.getByLabel('Capture file')).toBeVisible();
  await expect(
    page.getByText('No capture selected. Files stay on this device.', { exact: true }),
  ).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Capture overview' })).toHaveCount(0);
  expect(externalRequests).toEqual([]);
});
