import { test, expect } from '@playwright/test';

test('has title', async ({ page }) => {
  await page.goto('https://playwright.dev/');

  // Expect a title "to contain" a substring.
  await expect(page).toHaveTitle(/Playwright/);

  // Take a screenshot for visual verification
  const runId = process.env.RUN_ID || 'latest';
  const screenshotPath = `reports/${runId}/screenshots/homepage-${test.info().project.name}.png`;
  await page.screenshot({
    path: screenshotPath,
    fullPage: true,
  });

  // Attach screenshot to test report
  await test.info().attach('Homepage Screenshot', {
    path: screenshotPath,
    contentType: 'image/png',
  });
});

test('get started link', async ({ page }) => {
  await page.goto('https://playwright.dev/');

  // Click the get started link.
  await page.getByRole('link', { name: 'Get started' }).click();

  // Expects page to have a heading with the name of Installation.
  await expect(page.getByRole('heading', { name: 'Installation' })).toBeVisible();

  // Take a screenshot for visual verification
  const runId = process.env.RUN_ID || 'latest';
  const screenshotPath = `reports/${runId}/screenshots/get-started-${test.info().project.name}.png`;
  await page.screenshot({
    path: screenshotPath,
    fullPage: true,
  });

  // Attach screenshot to test report
  await test.info().attach('Get Started Screenshot', {
    path: screenshotPath,
    contentType: 'image/png',
  });
});
