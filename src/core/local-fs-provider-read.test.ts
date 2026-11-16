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

// Linux file names are bytes: a skill file named `caf\xe9.js` was listed as
// `caf�.js`, which then failed to open, so its code went unanalysed
// locally while a remote scan read it. (macOS and Windows reject such names.)
describe.skipIf(process.platform !== 'linux')('LocalFSProvider non-UTF-8 file names', () => {
  const fs = new LocalFSProvider();
  let dir: string;

  beforeAll(() => {
    dir = mkdtempSync(join(tmpdir(), 'vaso-names-'));
    const raw = (name: string) => Buffer.concat([Buffer.from(dir + '/'), Buffer.from(name, 'latin1')]);
    writeFileSync(raw('caf\xe9-\xff.js'), 'eval(process.argv[2])\n');
    mkdirSync(raw('\xffdir'));
    writeFileSync(Buffer.concat([raw('\xffdir'), Buffer.from('/inner.js')]), 'x');
    writeFileSync(join(dir, 'plain.js'), 'y');
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it('lists them as the probe does (U+FFFD) and reads the listed path', async () => {
    const entries = await fs.readdirEntries(dir, { recursive: true });
    const files = entries.filter(e => e.isFile).map(e => join(e.parentPath!, e.name)).sort();
    expect(files).toEqual([join(dir, 'caf�-�.js'), join(dir, 'plain.js'), join(dir, '�dir', 'inner.js')].sort());
    expect(await fs.readFile(join(dir, 'caf�-�.js'))).toContain('eval');
    expect(await fs.readFile(join(dir, '�dir', 'inner.js'))).toBe('x');
    expect((await fs.stat(join(dir, '�dir'))).isDirectory()).toBe(true);
    // UTF-8 names are untouched
    expect(await fs.readFile(join(dir, 'plain.js'))).toBe('y');
  });
});

describe.skipIf(process.platform === 'win32')('LocalFSProvider.homedir', () => {
  it('drops "."/".." segments and a trailing slash, as the probe does (snapshot paths match)', () => {
    const saved = process.env.HOME;
    try {
      for (const [spelled, want] of [['/home/u/.codex/..', '/home/u'], ['/home/u/', '/home/u'], ['/home/u/./x/../', '/home/u'], ['/home/u', '/home/u']]) {
        process.env.HOME = spelled;
        expect(new LocalFSProvider().homedir()).toBe(want);
      }
    } finally {
      process.env.HOME = saved;
    }
  });
});
