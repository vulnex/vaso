import { describe, it, expect } from 'vitest';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('../bin/vaso-quick.sh', import.meta.url));

describe.skipIf(process.platform === 'win32')('bin/vaso-quick.sh', () => {
  it('parses under bash (a syntax error aborts the quick scan mid-way)', () => {
    expect(() => execFileSync('bash', ['-n', script], { stdio: 'pipe' })).not.toThrow();
  });
});
