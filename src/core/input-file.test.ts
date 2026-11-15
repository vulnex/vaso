import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { readInputFile } from './input-file.js';
import { runRulesValidate } from '../commands/rules.js';

const posix = process.platform !== 'win32';

describe('readInputFile', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vaso-input-'));

  it('reads a regular file', async () => {
    const f = join(dir, 'a.yaml');
    writeFileSync(f, 'rules: []\n');
    expect(await readInputFile(f, 1024)).toBe('rules: []\n');
  });

  it('refuses a file over the limit', async () => {
    const f = join(dir, 'big.json');
    writeFileSync(f, 'x'.repeat(2048));
    await expect(readInputFile(f, 1024)).rejects.toMatchObject({ code: 'EFBIG' });
  });

  it('refuses a directory', async () => {
    await expect(readInputFile(dir, 1024)).rejects.toMatchObject({ code: 'EISDIR' });
  });

  it.skipIf(!posix)('refuses a FIFO without blocking', async () => {
    const fifo = join(dir, 'pipe');
    execFileSync('mkfifo', [fifo]);
    await expect(readInputFile(fifo, 1024)).rejects.toMatchObject({ code: 'EINVAL' });
  });

  it.skipIf(!posix)('refuses a device such as /dev/zero', async () => {
    await expect(readInputFile('/dev/zero', 1024)).rejects.toMatchObject({ code: 'EINVAL' });
  });

  it.skipIf(!posix)('vaso rules validate <fifo> exits 2 instead of hanging', async () => {
    const fifo = join(dir, 'rules-pipe');
    execFileSync('mkfifo', [fifo]);
    const errors: string[] = [];
    const orig = console.error;
    console.error = (...a: unknown[]) => { errors.push(a.join(' ')); };
    try {
      await runRulesValidate(fifo, {});
    } finally {
      console.error = orig;
    }
    expect(process.exitCode).toBe(2);
    expect(errors.join('\n')).toMatch(/not a regular file/);
    process.exitCode = 0;
  });
});
