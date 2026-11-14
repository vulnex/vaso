import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync, realpathSync } from 'node:fs';
import { join } from 'node:path';
// /tmp, not os.tmpdir(): macOS's per-user temp dir is 0700 and would block every walk
import { markUnreachable } from './permissions.js';
import { LocalFSProvider } from './local-fs-provider.js';
import { SnapshotFSProvider } from './snapshot-fs-provider.js';
import type { ProbeSnapshot } from './snapshot-types.js';

const posix = process.platform !== 'win32';

describe.runIf(posix)('markUnreachable follows symlinks to the real file', () => {
  let root: string;
  beforeEach(() => {
    root = realpathSync(mkdtempSync('/tmp/perm-sym-'));
    chmodSync(root, 0o755);
    mkdirSync(join(root, 'open'));
    mkdirSync(join(root, 'private'));
    chmodSync(join(root, 'open'), 0o755);
    chmodSync(join(root, 'private'), 0o700);
  });
  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  it('keeps a link in a private dir live when its target sits in an open dir', async () => {
    writeFileSync(join(root, 'open', 'cred.json'), '{}');
    chmodSync(join(root, 'open', 'cred.json'), 0o644);
    symlinkSync(join(root, 'open', 'cred.json'), join(root, 'private', 'cred.json'));
    const evidence = [{ file: join(root, 'private', 'cred.json'), detail: 'd' }];
    await markUnreachable(new LocalFSProvider(), evidence);
    expect(evidence[0]).not.toHaveProperty('mitigated');
  });

  it('keeps a file under a symlinked private-looking dir live when the real dir is open', async () => {
    mkdirSync(join(root, 'open', 'cfg'));
    chmodSync(join(root, 'open', 'cfg'), 0o755);
    writeFileSync(join(root, 'open', 'cfg', 'cred.json'), '{}');
    chmodSync(join(root, 'open', 'cfg', 'cred.json'), 0o644);
    symlinkSync(join(root, 'open', 'cfg'), join(root, 'private', 'cfg'));
    const evidence = [{ file: join(root, 'private', 'cfg', 'cred.json'), detail: 'd' }];
    await markUnreachable(new LocalFSProvider(), evidence);
    expect(evidence[0]).not.toHaveProperty('mitigated');
  });

  it('mitigates a link in an open dir when its target sits in a private dir', async () => {
    writeFileSync(join(root, 'private', 'cred.json'), '{}');
    chmodSync(join(root, 'private', 'cred.json'), 0o644);
    symlinkSync(join(root, 'private', 'cred.json'), join(root, 'open', 'cred.json'));
    const evidence = [{ file: join(root, 'open', 'cred.json'), detail: 'd' }];
    await markUnreachable(new LocalFSProvider(), evidence);
    expect(evidence[0]).toMatchObject({ mitigated: true });
    expect(evidence[0].detail).toContain(`${join(root, 'private')} (700)`);
  });
});

describe('markUnreachable on a snapshot', () => {
  function snap(overrides: Partial<ProbeSnapshot>): SnapshotFSProvider {
    return new SnapshotFSProvider({
      version: 1, hostname: 'h', platform: 'linux', homedir: '/home/u', timestamp: '2026-11-14T00:00:00Z',
      privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
      files: {}, directories: {}, commandOutputs: {}, env: {},
      ...overrides,
    });
  }

  it('walks the recorded link target, like a local scan', async () => {
    const fs = snap({
      files: { '/home/u/.codex/auth.json': { content: '{}', mode: 0o644, exists: true } },
      symlinks: { '/home/u/.codex/auth.json': '/srv/shared/auth.json' },
      directoryModes: { '/': 0o755, '/home': 0o755, '/home/u': 0o755, '/home/u/.codex': 0o700, '/srv': 0o755, '/srv/shared': 0o755 },
    });
    const evidence = [{ file: '/home/u/.codex/auth.json', detail: 'd' }];
    await markUnreachable(fs, evidence);
    expect(evidence[0]).not.toHaveProperty('mitigated');
  });

  it('still mitigates a plain file under a private dir', async () => {
    const fs = snap({
      files: { '/home/u/.codex/auth.json': { content: '{}', mode: 0o644, exists: true } },
      directoryModes: { '/': 0o755, '/home': 0o755, '/home/u': 0o755, '/home/u/.codex': 0o700 },
    });
    const evidence = [{ file: '/home/u/.codex/auth.json', detail: 'd' }];
    await markUnreachable(fs, evidence);
    expect(evidence[0]).toMatchObject({ mitigated: true });
  });
});
