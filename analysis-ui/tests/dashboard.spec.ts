import { test, expect } from '@playwright/test';

test('retained dataset preserves source identity, filters and issue provenance', async ({ page }) => {
  const errors: string[] = []; page.on('pageerror', e => errors.push(e.message));
  await page.goto('/');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('Agentic-Kibana');
  await expect(page.getByText('ANALYZED COMMIT')).toBeVisible();
  await page.getByRole('tab', { name: /^Issues/ }).click();
  await expect(page.getByLabel('Search issues')).toBeVisible();
  await page.getByLabel('Search issues').fill('assert');
  await expect(page.locator('.ant-table-tbody > tr.ant-table-row').first()).toBeVisible();
  await page.locator('.issue-link').first().click();
  await expect(page.getByRole('dialog', { name: 'Issue detail' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Supporting observations' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open exact source revision' })).toHaveAttribute('href', /\/blob\/[a-f0-9]{40}\//);
  const url = page.url(); await page.reload();
  await expect(page.getByRole('heading', { name: 'Supporting observations' })).toBeVisible();
  expect(page.url()).toEqual(url);
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog', { name: 'Issue detail' })).not.toBeVisible();
  expect(new URL(page.url()).hash).not.toContain('issue=');
  expect(errors).toEqual([]);
});

test('scanner failures remain separate from findings and navigation works on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/'); await page.getByRole('tab', { name: 'Scanners', exact: true }).click();
  await expect(page.getByText('Unavailable', { exact: true }).first()).toBeVisible();
  await expect(page.getByText('Atheris', { exact: true })).toBeVisible();
  await expect(page.getByText('Schemathesis', { exact: true })).toBeVisible();
  await expect(page.getByLabel('Branch or pull request')).toBeVisible();
});

test('untrusted messages render as text', async ({ page }) => {
  await page.route('**/findings.json', async route => {
    const response = await route.fetch(); const rows = await response.json();
    rows[0].message = '<img src=x onerror="window.injected=true">';
    await route.fulfill({ response, json: rows });
  });
  await page.goto('/'); await page.getByRole('tab', { name: /^Issues/ }).click();
  await page.getByLabel('Search issues').fill('window.injected');
  await expect(page.locator('.issue-link').first()).toContainText('<img');
  expect(await page.evaluate(() => (window as any).injected)).toBeUndefined();
});

test('Ant Design filters, pagination and responsive layout remain usable', async ({ page }, testInfo) => {
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Browse issues', exact: true })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('overview.png'), fullPage: true });
  await page.getByRole('tab', { name: /^Issues/ }).click();
  const first = await page.locator('.issue-link').first().textContent();
  await page.getByTitle('Next Page').click();
  await expect(page.locator('.issue-link').first()).not.toHaveText(first!);
  await page.getByLabel('Severity', { exact: true }).click();
  await page.getByTitle('HIGH', { exact: true }).click();
  await expect(page.locator('.ant-table-tbody > tr.ant-table-row').first()).toContainText('HIGH');
  await page.screenshot({ path: testInfo.outputPath('issues.png'), fullPage: true });
  await page.locator('.issue-link').first().click();
  await expect(page.getByRole('heading', { name: 'Supporting observations' })).toBeVisible();
  await page.screenshot({ path: testInfo.outputPath('detail.png') });
  await page.keyboard.press('Escape');
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('tab', { name: 'Overview', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Browse issues', exact: true })).toBeVisible();
  await expect(page.getByRole('dialog')).not.toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.screenshot({ path: testInfo.outputPath('mobile.png'), fullPage: true });
  await page.getByLabel('Branch or pull request').click();
  await expect(page.getByRole('listbox')).toBeAttached();
  await page.keyboard.press('Escape');
});
