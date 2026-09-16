import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: ['src/cli.ts'],
    format: ['esm'],
    target: 'node20',
    outDir: 'dist',
    clean: true,
    sourcemap: true,
    dts: false,
    splitting: false,
    shims: false,
    banner: {
      js: '#!/usr/bin/env node',
    },
  },
  {
    // Library entry (programmatic API) — no shebang, ships type declarations.
    entry: ['src/index.ts'],
    format: ['esm'],
    target: 'node20',
    outDir: 'dist',
    clean: false,
    sourcemap: true,
    dts: true,
    splitting: false,
    shims: false,
  },
]);
