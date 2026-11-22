import { describe, it, expect } from 'vitest';
import { HostFileNames, hostFileBase, safeHostname, sameDirectory } from './host-files.js';
import { mkdtemp, mkdir, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

describe('HostFileNames', () => {
  it('names a file after the hostname', () => {
    const names = new HostFileNames();
    expect(names.claim('web-1', 'root@10.0.0.1')).toBe('web-1');
    expect(names.claim('web-2', 'root@10.0.0.2')).toBe('web-2');
  });

  it('gives a second target with the same hostname its own file', () => {
    const names = new HostFileNames();
    expect(names.claim('ubuntu', 'root@10.0.0.1')).toBe('ubuntu');
    expect(names.claim('ubuntu', 'root@10.0.0.2')).toBe('ubuntu--root_10.0.0.2');
    expect(names.claim('ubuntu', 'ops@10.0.0.1:2222')).toBe('ubuntu--ops_10.0.0.1_2222');
  });

  it('returns the same name when a target claims again', () => {
    const names = new HostFileNames();
    expect(names.claim('ubuntu', 'a@h')).toBe('ubuntu');
    expect(names.claim('ubuntu', 'b@h')).toBe('ubuntu--b_h');
    expect(names.claim('ubuntu', 'a@h')).toBe('ubuntu');
  });

  it('keeps path separators out of names', () => {
    expect(safeHostname('../etc/passwd')).toBe('.._etc_passwd');
  });

  it('treats names differing only in case as one file (case-insensitive file systems)', () => {
    const names = new HostFileNames();
    expect(names.claim('Ubuntu', 'a@h1')).toBe('Ubuntu');
    expect(names.claim('ubuntu', 'b@h2')).toBe('ubuntu--b_h2');
  });

  it('numbers a name when even the label-suffixed one is taken', () => {
    const names = new HostFileNames();
    expect(names.claim('web--b_h', 'a@h')).toBe('web--b_h');
    expect(names.claim('web', 'x@y')).toBe('web');
    expect(names.claim('web', 'b@h')).toBe('web--b_h-2');
  });

  it('never names a file "", "." or ".."', () => {
    expect(hostFileBase('')).toBe('host');
    expect(hostFileBase('.')).toBe('host_');
    expect(hostFileBase('..')).toBe('host__');
    expect(new HostFileNames().claim('', 'a@h')).toBe('host');
  });
});

describe('long hostnames', () => {
  it('are cut to a file-name-safe length with a hash that keeps them distinct', () => {
    const a = hostFileBase('a'.repeat(300));
    const b = hostFileBase('a'.repeat(299) + 'b');
    expect(a.length).toBeLessThanOrEqual(100);
    expect(a).not.toBe(b);
    expect(a.startsWith('a'.repeat(80))).toBe(true);
    const names = new HostFileNames();
    const first = names.claim('x'.repeat(300), 'u@one');
    const second = names.claim('x'.repeat(300), 'u@' + 'l'.repeat(300));
    expect(second).not.toBe(first);
    expect(Buffer.byteLength(`${second}.json`)).toBeLessThan(255);
  });

  it('leaves ordinary hostnames as they were', () => {
    expect(hostFileBase('build-01.example.com')).toBe('build-01.example.com');
  });
});

describe('sameDirectory', () => {
  it('sees the same directory through a link and a .. path, but not a sibling', async () => {
    const root = await mkdtemp(join(tmpdir(), 'vaso-hf-'));
    try {
      await mkdir(join(root, 'out'));
      await mkdir(join(root, 'other'));
      await symlink(join(root, 'out'), join(root, 'link'));
      expect(await sameDirectory(join(root, 'out'), join(root, 'link'))).toBe(true);
      expect(await sameDirectory(join(root, 'out'), join(root, 'other', '..', 'out'))).toBe(true);
      expect(await sameDirectory(join(root, 'out'), join(root, 'other'))).toBe(false);
      expect(await sameDirectory(join(root, 'out'), join(root, 'missing'))).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
