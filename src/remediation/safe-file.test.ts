import { describe, it, expect, vi, afterEach } from 'vitest';
import { mkdtemp, writeFile, rm, chmod, stat, readFile, readdir, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { chmodNoFollow, withFixBoundary, writeRegularFile, renameKeepsMetadata, darwinPlain, linuxXattrNames, linuxFlagsPlain } from './safe-file.js';

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

  it.skipIf(!posix)('refuses a file a linked folder takes into a credential store, inside the roots too; not one written at its own path', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-sf-'));
    try {
      const { mkdir } = await import('node:fs/promises');
      await mkdir(join(dir, '.aws', 'cop'), { recursive: true });
      const real = join(dir, '.aws', 'cop', 'session-store.db');
      await writeFile(real, 'x');
      await chmod(real, 0o644);
      await symlink(join(dir, '.aws', 'cop'), join(dir, '.copilot'));
      await expect(withFixBoundary({ roots: [dir] }, () => chmodNoFollow(join(dir, '.copilot', 'session-store.db'), 0o600)))
        .rejects.toThrow(/is reached through a symlink into AWS credentials \(~\/\.aws\)/);
      expect((await stat(real)).mode & 0o777).toBe(0o644);
      await withFixBoundary({ roots: [dir] }, () => chmodNoFollow(real, 0o600));
      expect((await stat(real)).mode & 0o777).toBe(0o600);
    } finally {
      await rm(dir, { recursive: true, force: true });
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
      // a new inode (never truncated in place) wherever the platform can confirm nothing is lost
      if (await renameKeepsMetadata(f)) expect((await stat(f)).ino).not.toBe(before);
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

describe('renameKeepsMetadata output parsing', () => {
  it('macOS: accepts a plain file (kernel provenance tag only) and a directory without inheritable ACL', () => {
    expect(darwinPlain('-rw-------@ 1 501  20  - 1610 Nov 14 15:10 /h/.zeroclaw/config.toml\n\tcom.apple.provenance\t  11 \n', false)).toBe(true);
    expect(darwinPlain('drwxr-xr-x  7 501  20  -  224 Nov 14 15:10 /h/.zeroclaw\n 0: user:daemon allow list\n', true)).toBe(true);
  });
  it('macOS: refuses ACLs, attributes, flags, inheritable directory ACLs and anything unrecognised', () => {
    expect(darwinPlain('-rw-r--r--+ 1 501  20  - 1 Nov 14 15:10 f\n 0: user:nobody deny read\n', false)).toBe(false);
    expect(darwinPlain('-rw-r--r--@ 1 501  20  - 1 Nov 14 15:10 f\n\tcom.example.tag\t  4 \n', false)).toBe(false);
    // an attribute whose name starts like the kernel's tag, then a tab
    expect(darwinPlain('-rw-r--r--@ 1 501  20  - 1 Nov 14 15:10 f\n\tcom.apple.provenance\t11 \n\tcom.apple.provenance\tz\t1 \n', false)).toBe(false);
    expect(darwinPlain('-rw-r--r--@ 1 501  20  - 1 Nov 14 15:10 f\n\tcom.apple.provenance\t11 \n', false)).toBe(true);
    expect(darwinPlain('-rw-r--r--  1 501  20  hidden 1 Nov 14 15:10 f\n', false)).toBe(false);
    expect(darwinPlain('drwxr-xr-x@ 7 501  20  -  224 Nov 14 15:10 d\n 0: FFFF allow list,file_inherit\n', true)).toBe(false);
    expect(darwinPlain('', false)).toBe(false);
    expect(darwinPlain('-rw-r--r--  1 501  20  - 1 Nov 14 15:10 f\nsecond-line-of-a-name\n', false)).toBe(false);
  });
  it('Linux: any attribute on the file, a default ACL on the directory, or a user flag keeps the write in place', () => {
    expect(linuxXattrNames('')).toEqual([]);
    expect(linuxXattrNames('# file: /h/c.toml\nsystem.posix_acl_access\n\n')).toEqual(['system.posix_acl_access']);
    expect(linuxFlagsPlain('--------------e------- /h/c.toml\n')).toBe(true);
    expect(linuxFlagsPlain('----a---------e------- /h/c.toml\n')).toBe(false);
    expect(linuxFlagsPlain('')).toBe(false);
  });
});

const darwin = process.platform === 'darwin';
describe.skipIf(!darwin)('writeRegularFile keeps macOS metadata (in place)', () => {
  const sh = (cmd: string, ...args: string[]) => execFileSync(cmd, args, { stdio: 'pipe' }).toString();
  async function withFile(fn: (dir: string, f: string) => Promise<void>): Promise<void> {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-sf-md-'));
    const f = join(dir, 'config.toml');
    await writeFile(f, 'old');
    await chmod(f, 0o600);
    try { await fn(dir, f); } finally {
      try { sh('/usr/bin/chflags', 'nohidden', f); } catch { /* gone */ }
      await rm(dir, { recursive: true, force: true });
    }
  }
  it('keeps an ACL', () => withFile(async (_d, f) => {
    sh('/bin/chmod', '+a', 'user:nobody deny read', f);
    const ino = (await stat(f)).ino;
    await writeRegularFile(f, 'new');
    expect(await readFile(f, 'utf8')).toBe('new');
    expect((await stat(f)).ino).toBe(ino);
    expect(sh('/bin/ls', '-led', f)).toMatch(/nobody deny read/);
  }));
  it('keeps extended attributes', () => withFile(async (_d, f) => {
    sh('/usr/bin/xattr', '-w', 'com.example.tag', 'keep', f);
    await writeRegularFile(f, 'new');
    expect(sh('/usr/bin/xattr', '-p', 'com.example.tag', f).trim()).toBe('keep');
  }));
  it('keeps file flags', () => withFile(async (_d, f) => {
    sh('/usr/bin/chflags', 'hidden', f);
    await writeRegularFile(f, 'new');
    expect(sh('/bin/ls', '-lOd', f)).toMatch(/hidden/);
  }));
  it('does not pick up an inheritable directory ACL', () => withFile(async (dir, f) => {
    sh('/bin/chmod', '+a', 'user:daemon allow read,file_inherit', dir);
    const ino = (await stat(f)).ino;
    await writeRegularFile(f, 'new');
    expect((await stat(f)).ino).toBe(ino);
    expect(sh('/bin/ls', '-led', f)).not.toMatch(/daemon/);
  }));
  it('sees an inheritable ACL on the real directory behind a symlinked one', () => withFile(async (dir, f) => {
    sh('/bin/chmod', '+a', 'user:daemon allow read,file_inherit', dir);
    const link = `${dir}-link`;
    await symlink(dir, link);
    try {
      const viaLink = join(link, 'config.toml');
      expect(await renameKeepsMetadata(viaLink)).toBe(false);
      await writeRegularFile(viaLink, 'new');
      expect(sh('/bin/ls', '-led', f)).not.toMatch(/daemon/);
    } finally {
      await rm(link, { force: true });
    }
  }));
  it('still renames a plain file', () => withFile(async (_d, f) => {
    const ino = (await stat(f)).ino;
    expect(await renameKeepsMetadata(f)).toBe(true);
    await writeRegularFile(f, 'new');
    expect((await stat(f)).ino).not.toBe(ino);
  }));
});
