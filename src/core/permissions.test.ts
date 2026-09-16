import { describe, it, expect, vi } from 'vitest';
import type { FSProvider, PermissionFacts } from './fs-provider.js';
import {
  posixPermissionFacts,
  queryPermissions,
  readableByOthers,
  writableByOthers,
  accessibleByOthers,
} from './permissions.js';

function fsWith(overrides: Partial<FSProvider>): FSProvider {
  return {
    platform: 'linux',
    stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    ...overrides,
  } as FSProvider;
}

describe('posixPermissionFacts', () => {
  it('derives all six flags from a permissive mode', () => {
    expect(posixPermissionFacts(0o777)).toEqual({
      groupRead: true, groupWrite: true, groupExec: true,
      worldRead: true, worldWrite: true, worldExec: true,
      octal: '777',
      description: 'mode 777',
    });
  });

  it('reports owner-only modes as fully closed', () => {
    const f = posixPermissionFacts(0o700);
    expect(accessibleByOthers(f)).toBe(false);
    expect(f.octal).toBe('700');
  });

  it('masks file-type bits off a full stat mode word', () => {
    // 0o100644 = regular file, rw-r--r--
    const f = posixPermissionFacts(0o100644);
    expect(f.octal).toBe('644');
    expect(f.worldRead).toBe(true);
    expect(f.worldWrite).toBe(false);
  });

  it('zero-pads the octal string', () => {
    expect(posixPermissionFacts(0o007).octal).toBe('007');
  });
});

describe('predicates', () => {
  it('readableByOthers matches mode & 0o044 semantics', () => {
    expect(readableByOthers(posixPermissionFacts(0o640))).toBe(true);
    expect(readableByOthers(posixPermissionFacts(0o604))).toBe(true);
    expect(readableByOthers(posixPermissionFacts(0o622))).toBe(false);
  });

  it('writableByOthers matches mode & 0o022 semantics', () => {
    expect(writableByOthers(posixPermissionFacts(0o620))).toBe(true);
    expect(writableByOthers(posixPermissionFacts(0o602))).toBe(true);
    expect(writableByOthers(posixPermissionFacts(0o644))).toBe(false);
  });

  it('accessibleByOthers matches mode & 0o077 semantics', () => {
    expect(accessibleByOthers(posixPermissionFacts(0o600))).toBe(false);
    expect(accessibleByOthers(posixPermissionFacts(0o601))).toBe(true);
    expect(accessibleByOthers(posixPermissionFacts(0o610))).toBe(true);
  });
});

describe('queryPermissions', () => {
  it('derives facts from stat mode bits on POSIX providers', async () => {
    const fs = fsWith({
      stat: vi.fn(async () => ({ mode: 0o100600, isFile: () => true, isDirectory: () => false })),
    });
    const q = await queryPermissions(fs, '/x');
    expect(q).not.toBe('unsupported');
    expect((q as PermissionFacts).octal).toBe('600');
  });

  it("returns 'unsupported' on win32 when the provider has no permissions capability", async () => {
    const fs = fsWith({ platform: 'win32' });
    expect(await queryPermissions(fs, '/x')).toBe('unsupported');
    expect(fs.stat).not.toHaveBeenCalled();
  });

  it('prefers the provider permissions() capability over stat math', async () => {
    const acl: PermissionFacts = {
      groupRead: false, groupWrite: false, groupExec: false,
      worldRead: false, worldWrite: true, worldExec: false,
      description: 'ACL grants Everyone write',
    };
    const fs = fsWith({
      platform: 'win32',
      permissions: vi.fn(async () => acl),
    });
    expect(await queryPermissions(fs, '/x')).toEqual(acl);
    expect(fs.stat).not.toHaveBeenCalled();
  });

  it('propagates stat errors like the direct stat calls it replaces', async () => {
    const fs = fsWith({
      stat: vi.fn(async () => { throw new Error('ENOENT'); }),
    });
    await expect(queryPermissions(fs, '/gone')).rejects.toThrow('ENOENT');
  });
});
