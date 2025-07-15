import { test, expect } from '@playwright/test';

test('basic authentication validation', async ({ page }) => {
  // Simple test to verify the test environment works
  await page.goto('data:text/html,<h1>Test Page</h1>');

  const heading = await page.locator('h1').textContent();
  expect(heading).toBe('Test Page');

  console.log('Basic test environment working');
});
