import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['testing/e2e/**/*.e2e.test.ts'],
    testTimeout: 60_000,
    hookTimeout: 120_000,
    globalSetup: ['testing/e2e/global-setup.ts'],
    globalTeardown: ['testing/e2e/global-teardown.ts'],
  },
});
