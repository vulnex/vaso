import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import * as fsp from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { ScanContext } from '../core/types.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { restrictFilesToOwner } from './config-writer.js';
import { zc013 } from '../checks/zeroclaw/zc-013-secret-key-perms.js';

vi.mock('node:fs/promises', async (orig) => ({ ...(await orig<typeof import('node:fs/promises')>()) }));

const posix = process.platform !== 'win32';
const mode = (p: string) => statSync(p).mode & 0o7777;

describe.skipIf(!posix)('permission fixes clear group/other bits only', () => {
  let dir: string;
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'vaso-perm-fix-')); });
  afterEach(() => {
    vi.restoreAllMocks();
    rmSync(dir, { recursive: true, force: true });
  });

  it('ZC-013 turns a 0444 key into 0400, not 0600', async () => {
    const install = join(dir, '.zeroclaw');
    mkdirSync(install);
    const key = join(install, '.secret_key');
    writeFileSync(key, 'k');
    chmodSync(key, 0o444);
    const ctx = { installation: { agent: 'zeroclaw', installDir: install }, configs: [], platform: 'linux', fs: new LocalFSProvider() } as unknown as ScanContext;
    const r = await zc013.fix!(ctx);
    expect(r.applied).toBe(true);
    expect(mode(key)).toBe(0o400);
  });

  it('turns a 0777 directory into 0700 and a 0444 file into 0400', async () => {
    const d = join(dir, 'cfg');
    mkdirSync(d);
    chmodSync(d, 0o777);
    const f = join(d, 'mount-allowlist.json');
    writeFileSync(f, '{}');
    chmodSync(f, 0o444);
    const r = await restrictFilesToOwner('NC-002', [d, f]);
    expect(r.applied).toBe(true);
    expect(mode(d)).toBe(0o700);
    expect(mode(f)).toBe(0o400);
  });

  it('reports a chmod error instead of swallowing it', async () => {
    const f = join(dir, 'cred.json');
    writeFileSync(f, '{}');
    chmodSync(f, 0o644);
    const err = Object.assign(new Error('EPERM: operation not permitted'), { code: 'EPERM' });
    vi.spyOn(fsp, 'chmod').mockRejectedValue(err);
    vi.spyOn(fsp, 'open').mockRejectedValue(err);
    const r = await restrictFilesToOwner('CFG-020', [f]);
    expect(r.applied).toBe(false);
    expect(r.alreadyDone).toBeUndefined();
    expect(r.message).toContain('EPERM');
  });

  it('skips a missing file silently', async () => {
    const r = await restrictFilesToOwner('CFG-020', [join(dir, 'missing.json')]);
    expect(r).toMatchObject({ applied: false, alreadyDone: true });
  });
});
