import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm, chmod, stat, readFile, readdir, symlink } from 'node:fs/promises';
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

describe.skipIf(!posix)('writeRegularFile', () => {
  it('replaces the content by rename, keeping the mode, and leaves no temporary file', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-sf-'));
    try {
      const f = join(dir, 'config.toml');
      await writeFile(f, 'old');
      await chmod(f, 0o640);
      const before = (await stat(f)).ino;
      await writeRegularFile(f, 'new content');
      expect(await readFile(f, 'utf8')).toBe('new content');
      expect((await stat(f)).mode & 0o7777).toBe(0o640);
      expect((await stat(f)).ino).not.toBe(before); // a new inode: never truncated in place
      expect(await readdir(dir)).toEqual(['config.toml']);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('rewrites in place when the directory is read-only', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-sf-'));
    try {
      const f = join(dir, 'config.toml');
      await writeFile(f, 'old');
      await chmod(dir, 0o500);
      await writeRegularFile(f, 'new');
      expect(await readFile(f, 'utf8')).toBe('new');
    } finally {
      await chmod(dir, 0o700);
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('still refuses a read-only file and a symlink', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-sf-'));
    try {
      const f = join(dir, 'ro.toml');
      await writeFile(f, 'old');
      await chmod(f, 0o400);
      await expect(writeRegularFile(f, 'new')).rejects.toThrow();
      expect(await readFile(f, 'utf8')).toBe('old');
      const l = join(dir, 'link.toml');
      await symlink(f, l);
      await expect(writeRegularFile(l, 'new')).rejects.toThrow(/symlink/);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
