import { FullConfig } from '@playwright/test';
import dotenv from 'dotenv';
import path from 'path';

async function globalSetup(config: FullConfig): Promise<void> {
  // Load environment variables
  const envFile = process.env.ENV_FILE || '.env';
  dotenv.config({ path: path.resolve(process.cwd(), envFile) });
  
  console.log('**** Global setup started ****');
  console.log(`Environment: ${process.env.TEST_ENVIRONMENT || 'local'}`);
  console.log(`Base URL: ${process.env.BASE_URL}`);
  console.log(`Client: ${process.env.CLIENT_NAME || 'default'}`);
  
  // Set up any global state needed
  // For example: authenticate and save storage state
  
  // Get run ID from environment or create one
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const runId = process.env.RUN_ID || `run-${timestamp}`;
  process.env.RUN_ID = runId;
  
  // Create necessary directories with unique run folder
  const fs = await import('fs/promises');
  const directories = [
    `reports/${runId}/screenshots`,
    `reports/${runId}/videos`,
    `reports/${runId}/traces`,
    `reports/${runId}/html`,
    `reports/${runId}/json`,
    `reports/${runId}/junit`,
    `reports/${runId}/test-results`
  ];
  
  for (const dir of directories) {
    await fs.mkdir(dir, { recursive: true });
  }
  
  console.log(`**** Global setup completed - Run ID: ${runId} ****`);
}

export default globalSetup;