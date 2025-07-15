import { defineConfig, devices } from '@playwright/test';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

// Get __dirname equivalent for ES modules
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Load environment variables
dotenv.config({ path: path.resolve(__dirname, '.env') });

// Determine if running in CI
const isCI = !!process.env.CI;

// Generate run ID for this test run (only if not already set)
const runId =
  process.env.RUN_ID ??
  (() => {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const id = `run-${timestamp}`;
    process.env.RUN_ID = id;
    return id;
  })();

export default defineConfig({
  // Test directory
  testDir: './tests',

  // Test execution settings
  fullyParallel: true, // Run tests in parallel
  forbidOnly: isCI, // Fail if test.only is left in code
  retries: isCI ? 2 : 0, // Retry failed tests in CI
  ...(isCI && { workers: 4 }), // Number of parallel workers in CI

  // Test timeout settings
  timeout: 30000, // 30 seconds per test
  expect: {
    timeout: 10000, // 10 seconds for assertions
  },

  // Reporter configuration
  reporter: [
    ['list'], // Simple list output
    [
      'html',
      {
        outputFolder: `reports/${runId}/html`,
        open: 'never', // Don't auto-open report
      },
    ],
    [
      'json',
      {
        outputFile: `reports/${runId}/json/results.json`,
      },
    ],
    [
      'junit',
      {
        outputFile: `reports/${runId}/junit/results.xml`,
      },
    ],
  ],

  // Shared settings for all projects
  use: {
    // Base URL for navigation
    baseURL: process.env.BASE_URL ?? 'http://localhost:3000',

    // Artifacts
    trace: 'on-first-retry', // Collect trace on retry
    screenshot: 'only-on-failure', // Screenshot on failure
    video: 'retain-on-failure', // Keep video on failure

    // Timeouts
    actionTimeout: 15000, // 15 seconds for actions
    navigationTimeout: 30000, // 30 seconds for navigation

    // Browser context options
    viewport: { width: 1920, height: 1080 },
    ignoreHTTPSErrors: true,

    // Custom test id attribute
    testIdAttribute: 'data-testid',
  },

  // Output directory for test artifacts
  outputDir: `reports/${runId}/test-results`,

  // Global setup and teardown
  globalSetup: path.resolve(__dirname, './src/setup/global-setup.ts'),
  globalTeardown: path.resolve(__dirname, './src/setup/global-teardown.ts'),

  // Configure projects for different browsers
  projects: [
    {
      name: 'chromium',
      use: {
        ...devices['Desktop Chrome'],
        // Custom Chrome options
        launchOptions: {
          args: ['--disable-dev-shm-usage'],
        },
      },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
    {
      name: 'mobile-chrome',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'mobile-safari',
      use: { ...devices['iPhone 12'] },
    },
  ],

  // Web server configuration (conditionally included)
  ...(process.env.START_SERVER && {
    webServer: {
      command: 'npm run start',
      port: 3000,
      timeout: 120 * 1000,
      reuseExistingServer: !isCI,
    },
  }),
});
