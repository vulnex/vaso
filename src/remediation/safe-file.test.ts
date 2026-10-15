import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm, chmod, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { chmodNoFollow, withFixBoundary, writeRegularFile } from './safe-file.js';

const posix = process.platform !== 'win32';

describe('fix boundary', () => {
  afterEach(() => vi.restoreAllMocks());

  it.skipIf(!posix)('as root, refuses a file not owned by the installation owner, even inside the roots', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-sf-'));
    try {
      const f = join(dir, 'config.json');
      await writeFile(f, 'a');
      await chmod(f, 0o644);
      vi.spyOn(process, 'getuid').mockReturnValue(0);
      const other = (await stat(f)).uid + 1;
      await expect(withFixBoundary({ roots: [dir], ownerUid: other }, () => chmodNoFollow(f, 0o600))).rejects.toThrow(/not by the installation's owner/);
      await expect(withFixBoundary({ roots: [dir], ownerUid: other }, () => writeRegularFile(f, 'b'))).rejects.toThrow(/not by the installation's owner/);
      expect((await stat(f)).mode & 0o777).toBe(0o644);
      // the owner's own file passes
      await withFixBoundary({ roots: [dir], ownerUid: (await stat(f)).uid }, () => chmodNoFollow(f, 0o600));
      expect((await stat(f)).mode & 0o777).toBe(0o600);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it.skipIf(!posix)('refuses a path outside every root', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-sf-'));
    const other = await mkdtemp(join(tmpdir(), 'vaso-sf-other-'));
    try {
      const f = join(other, 'x.json');
      await writeFile(f, 'a');
      await expect(withFixBoundary({ roots: [dir] }, () => writeRegularFile(f, 'b'))).rejects.toThrow(/outside/);
    } finally {
      await rm(dir, { recursive: true, force: true });
      await rm(other, { recursive: true, force: true });
    }
  });

  it('refuses a relative path: it could not be backed up', async () => {
    await expect(writeRegularFile('.codex/config.toml', 'x')).rejects.toThrow(/not an absolute path/);
    await expect(chmodNoFollow('.codex/auth.json', 0o600)).rejects.toThrow(/not an absolute path/);
  });
});
