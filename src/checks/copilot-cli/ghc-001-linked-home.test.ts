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
