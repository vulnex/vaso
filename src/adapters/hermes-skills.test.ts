import { describe, it, expect } from 'vitest';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import type { FileEntry } from '../core/snapshot-types.js';
import { externalSkillDirs, hermesSkillRoots } from './hermes-skills.js';
import { hermesAdapter } from './hermes.js';

const HOME = '/home/alice';
const H = `${HOME}/.hermes`;

function snapshot(files: Record<string, string>, env: Record<string, string> = {}): SnapshotFSProvider {
  const entries: Record<string, FileEntry> = {};
  for (const [p, content] of Object.entries(files)) entries[p] = { content, mode: 0o644, exists: true };
  return new SnapshotFSProvider({
    version: 1, hostname: 'h', platform: 'linux', homedir: HOME, timestamp: '2026-11-22T00:00:00Z',
    privilege: { uid: 1000, username: 'alice', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['alice'], skippedPaths: [] },
    files: entries, directories: {}, commandOutputs: {}, env,
  });
}

describe('Hermes skill roots', () => {
  it('expands external_dirs as Hermes does (string or list, ~, ${VAR}, relative to the data root)', () => {
    const fs = snapshot({}, { TEAM: '/home/alice/team' });
    expect(externalSkillDirs({ skills: { external_dirs: '~/shared' } }, H, fs, HOME)).toEqual([`${HOME}/shared`]);
    expect(externalSkillDirs({ skills: { external_dirs: ['${TEAM}/skills', 'local', ' ', 7, '${UNSET}/x'] } }, H, fs, HOME))
      .toEqual(['/home/alice/team/skills', `${H}/local`]);
    expect(externalSkillDirs({ skills: {} }, H, fs, HOME)).toEqual([]);
    expect(externalSkillDirs(undefined, H, fs, HOME)).toEqual([]);
  });

  it('includes every profile\'s skills and external dirs', async () => {
    const fs = snapshot({
      [`${H}/skills/a/SKILL.md`]: 'x',
      [`${H}/profiles/coder/skills/b/SKILL.md`]: 'x',
      [`${H}/profiles/coder/config.yaml`]: 'skills:\n  external_dirs: ~/prof-skills\n',
      [`${HOME}/team-skills/c/SKILL.md`]: 'x',
      [`${HOME}/prof-skills/d/SKILL.md`]: 'x',
    });
    const { roots, unscanned } = await hermesSkillRoots(H, { skills: { external_dirs: ['~/team-skills', '/etc/skills'] } }, fs, HOME);
    expect(roots).toEqual([`${H}/skills`, `${H}/profiles/coder/skills`, `${HOME}/team-skills`, `${HOME}/prof-skills`]);
    expect(unscanned.map(u => u.path)).toEqual(['/etc/skills']);
  });

  it('the probe manifest collects profile skills and walks external_dirs', () => {
    const m = hermesAdapter.getProbeManifest!();
    expect(m.globPatterns).toContain('~/.hermes/profiles/*/skills/**');
    expect(m.configRoots).toContainEqual(expect.objectContaining({
      kind: 'tree', relative: 'config', expandEnv: true,
      keys: [['skills', 'external_dirs'], ['skills', 'external_dirs', '*']],
    }));
  });
});
