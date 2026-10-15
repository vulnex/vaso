import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, chmod, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadConfigIfPresent } from './load-if-present.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { captureConfigLoadErrors } from '../core/config-loader.js';

const isRoot = process.getuid?.() === 0;

describe('loadConfigIfPresent', () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'vaso-lip-')); });
  afterEach(async () => {
    await chmod(join(dir, 'locked'), 0o755).catch(() => undefined);
    await rm(dir, { recursive: true, force: true });
  });

  it('skips a missing file without recording anything', async () => {
    const { result, loadErrors: errors } = await captureConfigLoadErrors(() => loadConfigIfPresent(join(dir, 'nope.json'), new LocalFSProvider()));
    expect(result).toBeUndefined();
    expect(errors).toEqual([]);
  });

  it.skipIf(isRoot || process.platform === 'win32')('records a config behind an unreadable directory', async () => {
    const locked = join(dir, 'locked');
    await mkdir(locked);
    await writeFile(join(locked, 'settings.json'), '{"a":1}');
    await chmod(locked, 0o000);
    const { result, loadErrors: errors } = await captureConfigLoadErrors(() => loadConfigIfPresent(join(locked, 'settings.json'), new LocalFSProvider()));
    expect(result).toBeUndefined();
    expect(errors.map(e => e.stage)).toEqual(['read']);
  });
});
