# Phase 1: Foundation Setup - Enterprise Playwright TypeScript Framework

## Overview

This phase establishes the fundamental architecture for a production-ready Playwright testing framework using TypeScript. We're building a solid foundation that supports enterprise requirements including type safety, scalability, and maintainability.

## Project Initialization

### Step 1: Create Project Structure

```bash
# Create the main project directory
mkdir playwrightx
cd playwrightx

# Initialize package.json with pnpm (recommended for enterprise)
pnpm init

# Create the essential directory structure
mkdir -p src/{core,config,fixtures,pages,components,api,utils,reporters,setup}
mkdir -p tests
mkdir -p scripts docs reports/screenshots config/environments
```

### Step 2: Install Core Dependencies

```bash
# Core Playwright dependencies with latest version - follow prompts
pnpm create playwright

# Ensure pnpm saves exact versions (no ^ or ~ in package.json)
pnpm config set save-exact true

# TypeScript and type definitions
pnpm add -D typescript@latest @types/node@latest

# Code quality tools
pnpm add -D \
  eslint@latest \
  prettier@latest \
  eslint-config-prettier@latest \
  eslint-plugin-playwright@latest \
  @typescript-eslint/parser@latest \
  @typescript-eslint/eslint-plugin@latest

# Testing utilities
pnpm add -D dotenv@latest cross-env@latest

```

### Step 3: TypeScript Configuration

Create `tsconfig.json`:

```json
{
  "compilerOptions": {
    // Language and Environment
    "target": "ES2022",                      // Modern JavaScript features
    "lib": ["ES2022", "DOM", "DOM.Iterable"], // Include DOM types for browser automation
    "module": "ESNext",                      // Use ES modules
    "moduleResolution": "bundler",           // Modern module resolution
    
    // Type Checking
    "strict": true,                          // Enable all strict type checking
    "noUnusedLocals": true,                 // Error on unused variables
    "noUnusedParameters": true,              // Error on unused parameters
    "noImplicitReturns": true,              // Ensure all code paths return
    "noFallthroughCasesInSwitch": true,    // Prevent switch fallthrough bugs
    "exactOptionalPropertyTypes": true,     // Stricter optional property handling
    
    // Modules
    "resolveJsonModule": true,               // Import JSON files
    "esModuleInterop": true,                // Better CommonJS interop
    "allowSyntheticDefaultImports": true,    // Allow default imports
    
    // Emit
    "noEmit": true,                         // Don't generate JS files
    "skipLibCheck": true,                   // Skip type checking of dependencies
    
    // JavaScript Support
    "allowJs": true,                        // Allow importing JS files
    "checkJs": false,                       // Don't type-check JS files
    
    // Experimental
    "experimentalDecorators": true,         // Enable decorators
    "emitDecoratorMetadata": true,         // Emit decorator metadata
    
    // Path Mapping for cleaner imports
    "baseUrl": ".",
    "paths": {
      "@/*": ["src/*"],
      "@core/*": ["src/core/*"],
      "@config/*": ["src/config/*"],
      "@pages/*": ["src/pages/*"],
      "@components/*": ["src/components/*"],
      "@api/*": ["src/api/*"],
      "@utils/*": ["src/utils/*"],
      "@fixtures/*": ["src/fixtures/*"],
      "@tests/*": ["tests/*"]
    }
  },
  "include": [
    "src/**/*",
    "tests/**/*",
    "playwright.config.ts"
  ],
  "exclude": [
    "node_modules",
    "reports",
    "dist"
  ]
}
```

### Step 4: Playwright Configuration

Create `playwright.config.ts`:

```typescript
import { defineConfig, devices } from '@playwright/test';
import dotenv from 'dotenv';
import path from 'path';

// Load environment variables
dotenv.config({ path: path.resolve(__dirname, '.env') });

// Determine if running in CI
const isCI = !!process.env.CI;

export default defineConfig({
  // Test directory
  testDir: './tests',
  
  // Test execution settings
  fullyParallel: true,                    // Run tests in parallel
  forbidOnly: isCI,                       // Fail if test.only is left in code
  retries: isCI ? 2 : 0,                 // Retry failed tests in CI
  ...(isCI && { workers: 4 }),           // Number of parallel workers in CI
  
  // Test timeout settings
  timeout: 30000,                         // 30 seconds per test
  expect: {
    timeout: 10000                        // 10 seconds for assertions
  },
  
  // Reporter configuration
  reporter: [
    ['list'],                             // Simple list output
    ['html', { 
      outputFolder: 'reports/html',
      open: 'never'                       // Don't auto-open report
    }],
    ['json', { 
      outputFile: 'reports/json/results.json' 
    }],
    ['junit', { 
      outputFile: 'reports/junit/results.xml' 
    }]
  ],
  
  // Shared settings for all projects
  use: {
    // Base URL for navigation
    baseURL: process.env.BASE_URL || 'http://localhost:3000',
    
    // Artifacts
    trace: 'on-first-retry',              // Collect trace on retry
    screenshot: 'only-on-failure',        // Screenshot on failure
    video: 'retain-on-failure',           // Keep video on failure
    
    // Timeouts
    actionTimeout: 15000,                 // 15 seconds for actions
    navigationTimeout: 30000,             // 30 seconds for navigation
    
    // Browser context options
    viewport: { width: 1920, height: 1080 },
    ignoreHTTPSErrors: true,
    
    // Custom test id attribute
    testIdAttribute: 'data-testid'
  },
  
  // Output directory for test artifacts
  outputDir: 'reports/test-results',
  
  // Global setup and teardown
  globalSetup: require.resolve('./src/setup/global-setup.ts'),
  globalTeardown: require.resolve('./src/setup/global-teardown.ts'),
  
  // Configure projects for different browsers
  projects: [
    {
      name: 'chromium',
      use: { 
        ...devices['Desktop Chrome'],
        // Custom Chrome options
        launchOptions: {
          args: ['--disable-dev-shm-usage']
        }
      }
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] }
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] }
    },
    {
      name: 'mobile-chrome',
      use: { ...devices['Pixel 5'] }
    },
    {
      name: 'mobile-safari',
      use: { ...devices['iPhone 12'] }
    }
  ],
  
  // Web server configuration (conditionally included)
  ...(process.env.START_SERVER && {
    webServer: {
      command: 'npm run start',
      port: 3000,
      timeout: 120 * 1000,
      reuseExistingServer: !isCI
    }
  })
});
```

### Step 5: ESLint Configuration

Create `.eslintrc.json`:

```json
{
  "root": true,
  "parser": "@typescript-eslint/parser",
  "parserOptions": {
    "ecmaVersion": "latest",
    "sourceType": "module",
    "project": "./tsconfig.json"
  },
  "plugins": [
    "@typescript-eslint",
    "playwright"
  ],
  "extends": [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:@typescript-eslint/recommended-requiring-type-checking",
    "plugin:playwright/recommended",
    "prettier"
  ],
  "rules": {
    // TypeScript specific rules
    "@typescript-eslint/explicit-function-return-type": "error",
    "@typescript-eslint/no-explicit-any": "warn",
    "@typescript-eslint/no-unused-vars": ["error", {
      "argsIgnorePattern": "^_"
    }],
    
    // Playwright specific rules
    "playwright/no-wait-for-timeout": "warn",
    "playwright/no-skip-test": "warn",
    
    // General rules
    "no-console": ["warn", { 
      "allow": ["warn", "error", "info"] 
    }],
    "prefer-const": "error",
    "no-var": "error"
  },
  "overrides": [
    {
      "files": ["*.test.ts", "*.spec.ts"],
      "rules": {
        "@typescript-eslint/no-non-null-assertion": "off"
      }
    }
  ]
}
```

### Step 6: Prettier Configuration

Create `.prettierrc.json`:

```json
{
  "semi": true,
  "trailingComma": "es5",
  "singleQuote": true,
  "printWidth": 100,
  "tabWidth": 2,
  "useTabs": false,
  "arrowParens": "avoid",
  "endOfLine": "lf",
  "bracketSpacing": true,
  "bracketSameLine": false
}
```

### Step 7: Environment Configuration

Create `.env.template`:

```bash
# Application Settings
BASE_URL=http://localhost:3000
API_URL=http://localhost:3000/api

# Test Environment
TEST_ENVIRONMENT=local
CLIENT_NAME=default

# Browser Settings
HEADLESS=true
SLOW_MO=0
DEVTOOLS=false

# Timeouts (in milliseconds)
DEFAULT_TIMEOUT=30000
NAVIGATION_TIMEOUT=30000

# Parallel Execution
WORKERS=4

# Reporting
GENERATE_REPORT=true
OPEN_REPORT=false

# Authentication (if needed)
TEST_USERNAME=
TEST_PASSWORD=

# External Services
BROWSERSTACK_USERNAME=
BROWSERSTACK_ACCESS_KEY=
```

### Step 8: Create Initial Setup Files

Create `src/setup/global-setup.ts`:

```typescript
import { FullConfig } from '@playwright/test';
import dotenv from 'dotenv';
import path from 'path';

async function globalSetup(config: FullConfig): Promise<void> {
  // Load environment variables
  const envFile = process.env.ENV_FILE || '.env';
  dotenv.config({ path: path.resolve(process.cwd(), envFile) });
  
  console.log('🚀 Global setup started');
  console.log(`📁 Environment: ${process.env.TEST_ENVIRONMENT || 'local'}`);
  console.log(`🌐 Base URL: ${process.env.BASE_URL}`);
  console.log(`👥 Client: ${process.env.CLIENT_NAME || 'default'}`);
  
  // Set up any global state needed
  // For example: authenticate and save storage state
  
  // Create necessary directories
  const fs = await import('fs/promises');
  const directories = [
    'reports/screenshots',
    'reports/videos',
    'reports/traces',
    'reports/html',
    'reports/json',
    'reports/junit'
  ];
  
  for (const dir of directories) {
    await fs.mkdir(dir, { recursive: true });
  }
  
  console.log('✅ Global setup completed');
}

export default globalSetup;
```

Create `src/setup/global-teardown.ts`:

```typescript
import { FullConfig } from '@playwright/test';

async function globalTeardown(config: FullConfig): Promise<void> {
  console.log('🧹 Global teardown started');
  
  // Clean up any global resources
  // For example: close database connections, clean test data
  
  console.log('✅ Global teardown completed');
  
  // Generate summary report if needed
  if (process.env.GENERATE_REPORT === 'true') {
    console.log('📊 Generating test report...');
    // Report generation logic will be added in later phases
  }
}

export default globalTeardown;
```

### Step 9: Package.json Scripts

Update `package.json`:

```json
{
  "name": "playwright-enterprise-framework",
  "version": "1.0.0",
  "description": "Enterprise-grade Playwright testing framework with TypeScript",
  "scripts": {
    // Test execution scripts
    "test": "playwright test",
    "test:chrome": "playwright test --project=chromium",
    "test:firefox": "playwright test --project=firefox",
    "test:webkit": "playwright test --project=webkit",
    "test:mobile": "playwright test --project=mobile-chrome --project=mobile-safari",
    "test:headed": "playwright test --headed",
    "test:debug": "playwright test --debug",
    
    // Test categories
    "test:e2e": "playwright test tests/e2e",
    "test:api": "playwright test tests/api",
    "test:visual": "playwright test tests/visual",
    "test:performance": "playwright test tests/performance",
    
    // Utilities
    "playwright:install": "playwright install --with-deps",
    "report:open": "playwright show-report reports/html",
    "trace:open": "playwright show-trace",
    
    // Code quality
    "lint": "eslint . --ext .ts",
    "lint:fix": "eslint . --ext .ts --fix",
    "format": "prettier --write \"**/*.{ts,js,json,md}\"",
    "format:check": "prettier --check \"**/*.{ts,js,json,md}\"",
    "typecheck": "tsc --noEmit",
    
    // Pre-commit hook
    "pre-commit": "pnpm run typecheck && pnpm run lint && pnpm run format:check"
  },
  "keywords": [
    "playwright",
    "automation",
    "testing",
    "e2e",
    "typescript",
    "framework"
  ],
  "author": "Your Team",
  "license": "MIT",
  "engines": {
    "node": ">=18.0.0",
    "pnpm": ">=8.0.0"
  }
}
```

### Step 10: Initial Test File

Create `tests/e2e/example.test.ts`:

```typescript
import { test, expect } from '@playwright/test';

test.describe('Framework Setup Validation', () => {
  test('should load the application homepage', async ({ page }) => {
    // Navigate to the base URL
    await page.goto('/');
    
    // Verify the page loaded successfully
    await expect(page).toHaveTitle(/.*/, { timeout: 5000 });
    
    // Take a screenshot for visual verification
    await page.screenshot({ 
      path: 'reports/screenshots/homepage.png',
      fullPage: true 
    });
  });
  
  test('should handle navigation', async ({ page }) => {
    await page.goto('/');
    
    // Example: Click on a navigation link
    // await page.click('text=About');
    
    // Verify URL changed
    // await expect(page).toHaveURL(/.*about/);
  });
});
```

## How to Use Phase 1

### 1. Initial Setup
```bash
# Clone or create the project
git clone <your-repo-url>
cd playwright-enterprise-framework

# Install dependencies
pnpm install

# Install Playwright browsers
pnpm run playwright:install

# Copy environment template
cp .env.template .env

# Edit .env with your settings
```

### 2. Run Your First Test
```bash
# Run all tests
pnpm test

# Run specific browser
pnpm test:chrome

# Run with UI mode
pnpm test --ui

# Run in debug mode
pnpm test:debug
```

### 3. View Reports
```bash
# Open HTML report
pnpm run report:open

# Reports are available in:
# - reports/html/index.html (HTML report)
# - reports/json/results.json (JSON results)
# - reports/junit/results.xml (JUnit XML)
```

## Value Delivered in Phase 1

### 1. **Type Safety Foundation**
The TypeScript configuration provides compile-time error checking, preventing common runtime errors and making the codebase more maintainable. The strict type checking ensures that potential issues are caught during development rather than during test execution.

### 2. **Professional Project Structure**
The organized directory structure supports scalability from day one. Teams can easily locate and manage different types of tests, configurations, and utilities without confusion.

### 3. **Multi-Browser Support**
Out-of-the-box configuration for Chrome, Firefox, Safari, and mobile browsers ensures comprehensive cross-browser testing capability without additional setup.

### 4. **Development Best Practices**
ESLint and Prettier configurations enforce consistent code style across the team, reducing code review friction and improving code quality.

### 5. **Environment Flexibility**
The environment configuration system allows the same test suite to run against different environments (local, staging, production) without code changes.

### 6. **CI/CD Ready**
The configuration includes CI-specific settings, making it easy to integrate with any CI/CD pipeline from the start.

## Next Phase Preview: Core Architecture

In Phase 2, we'll build upon this foundation to create the core architecture components that will power our testing framework:

1. **Enhanced Base Page Class**: A sophisticated page object base class with built-in error handling, retry logic, and performance tracking
2. **Component Architecture**: Reusable UI component classes for common elements like forms, tables, and modals
3. **Custom Test Fixtures**: Extended Playwright test fixtures for test data management and common operations
4. **Error Handling System**: Comprehensive error capture and reporting for better debugging
5. **Logging Infrastructure**: Structured logging for test execution tracking and debugging

The core architecture phase will transform our basic setup into a robust framework capable of handling complex enterprise testing scenarios with reliability and maintainability.