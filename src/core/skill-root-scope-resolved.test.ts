import { describe, expect, it } from 'vitest';
import { SnapshotFSProvider } from './snapshot-fs-provider.js';
import type { ProbeSnapshot } from './snapshot-types.js';
import { skillRootGap, withinHome } from './skill-root-scope.js';
import { validateSnapshot } from './snapshot-load.js';

/**
 * A linked home spelled the other way in a snapshot: the link isn't recorded
 * (keys stay as spelled), where it resolves is (resolvedDirs). Derived
 * workspace-<id> siblings spelled that way are in the home, as a local scan
 * resolves them — not "outside the user's home".
 */
function snapshot(homedir: string, extra: Partial<ProbeSnapshot> = {}): SnapshotFSProvider {
  return new SnapshotFSProvider({
    version: 1,
    hostname: 'box',
    platform: 'linux',
    homedir,
    timestamp: '2026-11-15T00:00:00Z',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: { [`${homedir}/.picoclaw/config.json`]: { content: '{}', mode: 0o100600, exists: true } },
    directories: {},
    commandOutputs: {},
    env: {},
    directoryModes: { [homedir]: 0o40755 },
    ...extra,
  });
}

describe('config-set skill roots under a linked home spelled the other way (snapshots)', () => {
  // Fedora Silverblue: /home → /var/home
  const real = '/var/home/u';
  const link = '/home/u';

  it('home real, workspace spelled through the link', async () => {
    const dir = `${link}/workspace-evil/skills`;
    expect(await skillRootGap(snapshot(real), dir, real)).toBe('outside');
    const fs = snapshot(real, { resolvedDirs: { [link]: real } });
    expect(await skillRootGap(fs, dir, real)).toBeUndefined();
    expect(await withinHome(fs, dir, real)).toBe(true);
  });

  it('home a link, workspace spelled the real way', async () => {
    const dir = `${real}/workspace-evil/skills`;
    expect(await skillRootGap(snapshot(link), dir, link)).toBe('outside');
    expect(await skillRootGap(snapshot(link, { resolvedDirs: { [link]: real } }), dir, link)).toBeUndefined();
  });

  it('still refuses what lies outside the home or in a credential store', async () => {
    const fs = snapshot(real, { resolvedDirs: { [link]: real } });
    expect(await skillRootGap(fs, '/var/home/other/workspace-x/skills', real)).toBe('outside');
    expect(await skillRootGap(fs, '/home/other/workspace-x/skills', real)).toBe('outside');
    expect(await skillRootGap(fs, '/etc/workspace-x/skills', real)).toBe('outside');
    expect(await skillRootGap(fs, '/opt/workspace-x/skills', real)).toBeUndefined();
    expect(await skillRootGap(fs, `${link}/.ssh/skills`, real)).toBe('outside');
    expect(await skillRootGap(fs, link, real)).toBe('home');
  });

  it('resolvedDir maps the longest recorded directory only at a component boundary', () => {
    const fs = snapshot(real, { resolvedDirs: { [link]: real } });
    expect(fs.resolvedDir(`${link}/a/b`)).toBe(`${real}/a/b`);
    expect(fs.resolvedDir(link)).toBe(real);
    expect(fs.resolvedDir(`${link}2/a`)).toBe(`${link}2/a`);
    expect(snapshot(real).resolvedDir(`${link}/a`)).toBe(`${link}/a`);
  });

  it('snapshot loading accepts normalized absolute paths only', () => {
    const base = { version: 1, hostname: 'h', platform: 'linux', homedir: real, timestamp: 't',
      privilege: { uid: 1, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: [], skippedPaths: [] },
      files: {}, directories: {}, commandOutputs: {}, env: {} };
    expect(validateSnapshot({ ...base, resolvedDirs: { [link]: real } })).toEqual([]);
    expect(validateSnapshot({ ...base, resolvedDirs: { 'rel/x': real } }).join()).toMatch(/resolvedDirs/);
    expect(validateSnapshot({ ...base, resolvedDirs: { [link]: '/var/../etc' } }).join()).toMatch(/resolvedDirs/);
    expect(validateSnapshot({ ...base, resolvedDirs: { [link]: 3 } }).join()).toMatch(/resolvedDirs/);
  });
});
