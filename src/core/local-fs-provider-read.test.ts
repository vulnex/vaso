import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { LocalFSProvider } from './local-fs-provider.js';

// A FIFO or device planted where a config or skill file is expected must not
// hang or exhaust the scan.
describe.skipIf(process.platform === 'win32')('LocalFSProvider reads regular files only', () => {
  const fs = new LocalFSProvider();
  let dir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'vaso-read-'));
    writeFileSync(join(dir, 'ok.json'), '{"a":1}');
    execFileSync('mkfifo', [join(dir, 'pipe.json')]);
    symlinkSync('/dev/zero', join(dir, 'zero.md'));
    symlinkSync(join(dir, 'ok.json'), join(dir, 'link.json'));
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('reads regular files and symlinks to them', async () => {
    expect(await fs.readFile(join(dir, 'ok.json'))).toBe('{"a":1}');
    expect(await fs.readFile(join(dir, 'link.json'))).toBe('{"a":1}');
    expect(Buffer.from(await fs.readBytes(join(dir, 'ok.json'))).toString()).toBe('{"a":1}');
  });

  it('rejects a FIFO without blocking', async () => {
    await expect(fs.readFile(join(dir, 'pipe.json'))).rejects.toThrow(/not a regular file/);
  }, 5000);

  it('rejects /dev/zero instead of reading forever', async () => {
    await expect(fs.readBytes(join(dir, 'zero.md'))).rejects.toThrow(/not a regular file/);
  }, 5000);

  it('rejects a directory with EISDIR (config loaders treat it as absent)', async () => {
    await expect(fs.readFile(dir)).rejects.toMatchObject({ code: 'EISDIR' });
  });
});

// One unreadable folder must not hide the rest of a skill tree (Node's
// recursive readdir rejects the whole walk on the first EACCES).
describe.skipIf(process.platform === 'win32' || process.getuid?.() === 0)('LocalFSProvider recursive readdirEntries', () => {
  const fs = new LocalFSProvider();
  let dir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'vaso-walk-'));
    mkdirSync(join(dir, 'a/b'), { recursive: true });
    writeFileSync(join(dir, 'a/b/evil.js'), 'eval(1)');
    mkdirSync(join(dir, 'locked/inner'), { recursive: true });
    writeFileSync(join(dir, 'locked/inner/x.js'), '');
    chmodSync(join(dir, 'locked'), 0o000);
    symlinkSync(join(dir, 'a'), join(dir, 'link-to-a'));
  });
  afterAll(() => {
    chmodSync(join(dir, 'locked'), 0o755);
    rmSync(dir, { recursive: true, force: true });
  });

  it('skips unreadable subdirectories and keeps walking', async () => {
    const entries = await fs.readdirEntries(dir, { recursive: true });
    const files = entries.filter(e => e.isFile).map(e => join(e.parentPath!, e.name));
    expect(files).toEqual([join(dir, 'a/b/evil.js')]);
    expect(entries.find(e => e.name === 'locked')).toMatchObject({ isDirectory: true });
    // symlinked directories are listed, not entered
    expect(entries.find(e => e.name === 'link-to-a')).toMatchObject({ isSymbolicLink: true, isDirectory: false });
  });

  it('still fails when the root itself cannot be read', async () => {
    await expect(fs.readdirEntries(join(dir, 'missing'), { recursive: true })).rejects.toThrow();
  });
});
