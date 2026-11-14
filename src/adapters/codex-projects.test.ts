import { describe, it, expect } from 'vitest';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import type { FileEntry } from '../core/snapshot-types.js';
import { codexAdapter, isCollectedProjectRoot } from './codex.js';
import { codexChecks } from '../checks/codex/index.js';

const HOME = '/home/u';

function snapshot(files: Record<string, string>): SnapshotFSProvider {
  const entries: Record<string, FileEntry> = {};
  for (const [p, content] of Object.entries(files)) entries[p] = { content, mode: 0o644, exists: true };
  return new SnapshotFSProvider({
    version: 1, hostname: 'h', platform: 'linux', homedir: HOME, timestamp: '2026-11-14T00:00:00Z',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: entries, directories: {}, commandOutputs: {}, env: {},
  });
}

describe('Codex trusted-project layers on remote scans', () => {
  it('the probe manifest collects .codex layers and root instructions under the usual clone dirs', () => {
    const globs = codexAdapter.getProbeManifest!().globPatterns;
    const project = globs.filter(g => g.includes('.codex/config.toml') && !g.startsWith('~/.codex'));
    expect(project).toHaveLength(2);
    for (const g of project) expect(g).toContain('[sS][rR][cC]');
    expect(globs.some(g => g.endsWith('/*/AGENTS.md'))).toBe(true);
    expect(globs.some(g => g.endsWith('/*/*/.codex/rules/*.rules'))).toBe(true);
  });

  it('knows which project roots the manifest covers', () => {
    expect(isCollectedProjectRoot(`${HOME}/work/repo`, HOME)).toBe(true);
    expect(isCollectedProjectRoot(`${HOME}/Projects/org/repo`, HOME)).toBe(true);
    expect(isCollectedProjectRoot(`${HOME}/SRC/repo/`, HOME)).toBe(true);
    expect(isCollectedProjectRoot(`${HOME}/work`, HOME)).toBe(false);
    expect(isCollectedProjectRoot(`${HOME}/work/a/b/c`, HOME)).toBe(false);
    expect(isCollectedProjectRoot(`${HOME}/Documents/repo`, HOME)).toBe(false);
    expect(isCollectedProjectRoot('/opt/repo', HOME)).toBe(false);
  });

  it('loads a collected trusted project layer from a snapshot and notes uncovered ones', async () => {
    const fs = snapshot({
      [`${HOME}/.codex/config.toml`]: [
        `[projects."${HOME}/work/repo"]`, 'trust_level = "trusted"',
        '[projects."/opt/elsewhere"]', 'trust_level = "trusted"', '',
      ].join('\n'),
      [`${HOME}/work/repo/.codex/config.toml`]: 'approval_policy = "never"\n',
    });
    const installs = await codexAdapter.detect({ fs });
    const project = installs.find(i => i.profile === 'project');
    expect(project?.installDir).toBe(`${HOME}/work/repo/.codex`);

    const user = installs.find(i => !i.profile)!;
    const cdx006 = codexChecks.find(c => c.id === 'CDX-006')!;
    const r = await cdx006.run({ installation: user, configs: user.configFiles, platform: 'linux', fs });
    expect(r.passed).toBe(true);
    expect(r.message).toContain('/opt/elsewhere not verified');
    expect(r.message).not.toContain('work/repo');
  });
});
