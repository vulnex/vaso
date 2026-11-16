import { describe, expect, it } from 'vitest';
import { SnapshotFSProvider } from '../../core/snapshot-fs-provider.js';
import type { ProbeSnapshot } from '../../core/snapshot-types.js';
import type { ScanContext } from '../../core/types.js';
import { copilotCliChecks } from './index.js';

const check = copilotCliChecks.find(c => c.id === 'GHC-001')!;

/**
 * HOME is a link (/home → /var/home) and a store file links into the home by
 * its real spelling. A snapshot keeps the home as spelled and records where it
 * resolves (resolvedDirs): the target is in the home, as a local scan sees it.
 */
function snapshotFs(resolvedDirs?: Record<string, string>): SnapshotFSProvider {
  const link = '/home/u';
  const real = '/var/home/u';
  const snap: ProbeSnapshot = {
    version: 1,
    hostname: 'box',
    platform: 'linux',
    homedir: link,
    timestamp: '2026-11-15T00:00:00Z',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: {
      [`${link}/.copilot/config.json`]: { content: '{}', mode: 0o100600, exists: true },
      [`${link}/.copilot/mcp-secrets/a.json`]: { content: '', mode: 0o100644, exists: true, contentOmitted: true, omitted: 'metadata' },
    },
    directories: { [`${link}/.copilot`]: ['config.json', 'mcp-secrets/'], [`${link}/.copilot/mcp-secrets`]: ['a.json'] },
    symlinks: { [`${link}/.copilot/mcp-secrets/a.json`]: `${real}/data/a.json` },
    commandOutputs: {},
    env: {},
    directoryModes: { [link]: 0o40700, [`${link}/.copilot`]: 0o40700, [`${link}/.copilot/mcp-secrets`]: 0o40700, [`${real}/data`]: 0o40755 },
    ...(resolvedDirs ? { resolvedDirs } : {}),
  };
  return new SnapshotFSProvider(snap);
}

function ctx(fs: SnapshotFSProvider): ScanContext {
  const installDir = '/home/u/.copilot';
  return {
    installation: { agent: 'copilot-cli', installDir, configFiles: [] },
    configs: [],
    platform: 'linux',
    fs,
  };
}

describe('GHC-001 under a linked home (snapshots)', () => {
  it('judges a store link into the home by its real spelling as the agent\'s own file', async () => {
    const r = await check.run(ctx(snapshotFs({ '/home/u': '/var/home/u' })));
    expect(r.message).not.toMatch(/outside the store and the home/);
    expect(r.evidence?.map(e => e.file)).toEqual(['/home/u/.copilot/mcp-secrets/a.json']);
    expect(r.evidence?.[0].detail).toMatch(/readable by group\/other/);
  });

  it('without the recorded resolution the target reads as outside the home', async () => {
    const r = await check.run(ctx(snapshotFs()));
    expect(r.message).toMatch(/outside the store and the home/);
  });
});

/** A plain home with the given store files, listings and links (as a probe records them). */
function storeSnapshot(extra: Pick<ProbeSnapshot, 'files' | 'directories' | 'symlinks'> & { directoryModes?: Record<string, number> }): SnapshotFSProvider {
  const home = '/home/u';
  return new SnapshotFSProvider({
    version: 1,
    hostname: 'box',
    platform: 'linux',
    homedir: home,
    timestamp: '2026-11-16T00:00:00Z',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: { [`${home}/.copilot/config.json`]: { content: '{}', mode: 0o100600, exists: true }, ...extra.files },
    directories: extra.directories,
    symlinks: extra.symlinks,
    commandOutputs: {},
    env: {},
    directoryModes: { [home]: 0o40755, [`${home}/.copilot`]: 0o40700, ...extra.directoryModes },
  });
}

const meta = (mode: number) => ({ content: '', mode, exists: true, contentOmitted: true, omitted: 'metadata' as const });

describe('GHC-001 store links on remote scans', () => {
  it('a store folder that is itself a link into a credential store: one warning, as locally', async () => {
    const fs = storeSnapshot({
      files: { '/home/u/.copilot/session-state/credentials': meta(0o100644) },
      directories: { '/home/u/.copilot': ['config.json', 'session-state'], '/home/u/.copilot/session-state': ['credentials'] },
      symlinks: { '/home/u/.copilot/session-state': '/home/u/.aws' },
      directoryModes: { '/home/u/.copilot/session-state': 0o40777 },
    });
    const r = await check.run(ctx(fs));
    expect(r.severity).toBe('warning');
    expect(r.fixable).toBe(false);
    expect(r.evidence?.map(e => e.file)).toEqual(['/home/u/.copilot/session-state']);
    expect(r.evidence?.[0].detail).toMatch(/^session-state\/ itself is a link to the folder \/home\/u\/\.aws \(AWS credentials/);
  });

  it('a linked session folder reached through a chain of links resolves where the chain ends', async () => {
    const fs = storeSnapshot({
      files: {},
      directories: { '/home/u/.copilot': ['config.json', 'session-state/'], '/home/u/.copilot/session-state': ['abc'] },
      symlinks: { '/home/u/.copilot/session-state/abc': '/home/u/hop', '/home/u/hop': '/srv/out/s' },
      directoryModes: { '/home/u/.copilot/session-state': 0o40700, '/home/u/.copilot/session-state/abc': 0o40755 },
    });
    const r = await check.run(ctx(fs));
    expect(r.severity).toBe('warning');
    expect(r.message).toMatch(/1 store link\(s\) point outside the store and the home/);
    expect(r.evidence?.map(e => [e.file, e.snippet])).toEqual([['/home/u/.copilot/session-state/abc', '-> /srv/out/s']]);
  });

  it('a file link into a credential store behind a followed session folder is judged, as locally', async () => {
    const fs = storeSnapshot({
      files: {
        '/home/u/.copilot/session-state/abc/events.jsonl': meta(0o100600),
        '/home/u/.copilot/session-state/abc/k.jsonl': meta(0o100644),
      },
      directories: { '/home/u/.copilot': ['config.json', 'session-state/'], '/home/u/.copilot/session-state': ['abc'] },
      symlinks: {
        '/home/u/.copilot/session-state/abc': '/home/u/sess',
        '/home/u/.copilot/session-state/abc/k.jsonl': '/home/u/.ssh/id_rsa',
        '/home/u/sess/k.jsonl': '/home/u/.ssh/id_rsa',
      },
      directoryModes: { '/home/u/.copilot/session-state': 0o40700, '/home/u/.copilot/session-state/abc': 0o40755 },
    });
    const r = await check.run(ctx(fs));
    expect(r.passed).toBe(false);
    expect(r.evidence?.map(e => e.file)).toEqual(['/home/u/.copilot/session-state/abc/k.jsonl']);
    expect(r.message).not.toMatch(/Not verified/);
  });
});
