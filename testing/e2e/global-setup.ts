import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { execSync } from 'node:child_process';

const PROJECT_ROOT = resolve(import.meta.dirname, '../..');

export default function globalSetup() {
  const cliPath = resolve(PROJECT_ROOT, 'dist/cli.js');

  if (!existsSync(cliPath)) {
    console.log('[e2e] dist/cli.js not found — running npm run build...');
    execSync('npm run build', { cwd: PROJECT_ROOT, stdio: 'inherit' });
  }
}
