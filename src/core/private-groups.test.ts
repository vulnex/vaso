import { describe, it, expect } from 'vitest';
import type { FSProvider } from './fs-provider.js';
import { parsePrivateGroups } from './private-groups.js';
import { markUnreachable, queryPermissions, readableByOthers } from './permissions.js';
import { SnapshotFSProvider } from './snapshot-fs-provider.js';
import type { Evidence } from './types.js';
import type { ProbeSnapshot } from './snapshot-types.js';

// Same fixture as probe/collector_test.go TestParsePrivateGroups — both sides must agree
const PASSWD = 'root:x:0:0:root:/root:/bin/bash\ncarol:x:1000:1000:Carol:/home/carol:/bin/bash\nalice:x:1001:100:,,,:/home/alice:/bin/bash\nbob:x:1002:100::/home/bob:/bin/sh\nshared:x:1003:1003::/home/shared:/bin/sh\n';
const GROUP = 'root:x:0:\ncarol:x:1000:\nusers:x:100:\nshared:x:1003:alice\ndocker:x:983:carol\n';

describe('parsePrivateGroups', () => {
  it('finds groups named after their single member, ignoring shared ones', () => {
    expect([...parsePrivateGroups(PASSWD, GROUP)]).toEqual([[0, 0], [1000, 1000]]);
  });
});

function fsWith(platform: NodeJS.Platform, modes: Record<string, number>, owners: Record<string, [number, number]>): FSProvider {
  return {
    platform,
    stat: async (p: string) => {
      if (!(p in modes)) throw new Error('ENOENT');
      return { mode: modes[p], isFile: () => true, isDirectory: () => false };
    },
    ownership: async (p: string) => (owners[p] ? { uid: owners[p][0], gid: owners[p][1] } : undefined),
    privateGroups: async () => parsePrivateGroups(PASSWD, GROUP),
  } as unknown as FSProvider;
}

describe('queryPermissions — user-private groups', () => {
  const file = '/home/carol/.local/share/devin/credentials.toml';

  it('drops group access on Linux when the group is the owner\'s private group', async () => {
    const perms = await queryPermissions(fsWith('linux', { [file]: 0o664 }, { [file]: [1000, 1000] }), file);
    expect(perms !== 'unsupported' && perms.groupRead).toBe(false);
    // World bits are untouched (664 stays world-readable; a 0750 home blocks that)
    expect(perms !== 'unsupported' && readableByOthers(perms) && perms.worldRead).toBe(true);
    expect(perms !== 'unsupported' && perms.octal).toBe('664');
  });

  it('keeps group access for shared groups, foreign owners and on macOS', async () => {
    const shared = await queryPermissions(fsWith('linux', { [file]: 0o660 }, { [file]: [1001, 100] }), file);
    expect(shared !== 'unsupported' && shared.groupRead).toBe(true);
    const foreign = await queryPermissions(fsWith('linux', { [file]: 0o660 }, { [file]: [1001, 1000] }), file);
    expect(foreign !== 'unsupported' && foreign.groupRead).toBe(true);
    const mac = await queryPermissions(fsWith('darwin', { [file]: 0o660 }, { [file]: [1000, 1000] }), file);
    expect(mac !== 'unsupported' && mac.groupRead).toBe(true);
  });

  it('a 0750 home with a private group blocks every other user', async () => {
    const f = '/home/carol/.gemini/settings.json';
    const fs = fsWith('linux',
      { [f]: 0o664, '/home/carol/.gemini': 0o775, '/home/carol': 0o750, '/home': 0o755, '/': 0o755 },
      { [f]: [1000, 1000], '/home/carol/.gemini': [1000, 1000], '/home/carol': [1000, 1000], '/home': [0, 0], '/': [0, 0] });
    const evidence: Evidence[] = [{ file: f, detail: 'readable by group/other' }];
    await markUnreachable(fs, evidence);
    expect(evidence[0].mitigated).toBe(true);
  });

  it('works from a remote snapshot (probe ≥ 1.1.0) and is a no-op for older snapshots', async () => {
    const base = {
      version: 1, hostname: 'h', platform: 'linux', homedir: '/home/carol', timestamp: 't',
      privilege: { uid: 1000, username: 'carol', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: [], skippedPaths: [] },
      files: { [file]: { content: '', mode: 0o664, exists: true } }, directories: {}, commandOutputs: {}, env: {},
    } as unknown as ProbeSnapshot;
    const remote = await queryPermissions(new SnapshotFSProvider({ ...base, owners: { [file]: [1000, 1000] }, privateGroups: { '1000': 1000 } }), file);
    expect(remote !== 'unsupported' && remote.groupRead).toBe(false);
    const old = await queryPermissions(new SnapshotFSProvider(base), file);
    expect(old !== 'unsupported' && old.groupRead).toBe(true);
  });
});
