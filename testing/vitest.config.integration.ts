import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['testing/integration/**/*.integration.test.ts'],
    testTimeout: 120_000,
    // A cold runner builds each agent image on first use; files run one at a
    // time so concurrent first builds don't starve each other
    hookTimeout: 300_000,
    fileParallelism: false,
  },
});
