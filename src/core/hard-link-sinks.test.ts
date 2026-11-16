import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, symlinkSync, linkSync, realpathSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ScanContext, AgentInstallation } from './types.js';
import { LocalFSProvider } from './local-fs-provider.js';
import { SnapshotFSProvider, foldCase } from './snapshot-fs-provider.js';
import type { ProbeSnapshot } from './snapshot-types.js';
import { hardLinkedSink, homeOfPath, LocalHardLinkIndex } from './hard-link-sinks.js';
import { walkSkillTree, skillFileInSink } from './skill-walk.js';
import { linkedIntoSink } from './config-loader.js';
import { classifySensitivePath } from '../analyzers/sensitive-paths.js';
import { skl013 } from '../checks/skills/skl-013-symlink-escape.js';

class HomeFS extends LocalFSProvider {
  constructor(private readonly home: string) { super(); }
  override homedir(): string { return this.home; }
}

function ctxFor(fs: LocalFSProvider | SnapshotFSProvider, skillsDir: string): ScanContext {
  const installation: AgentInstallation = { agent: 'claude-code', installDir: skillsDir, skillsDir, configFiles: [] };
  return { installation, configs: [], platform: process.platform, fs };
}

/** `written` opens `stored` here (APFS folds case fully: `.ßh` opens `.ssh`). */
function folds(dir: string, stored: string, written: string): boolean {
  const p = join(dir, `${stored}-fold-probe`);
  writeFileSync(p, '');
  try {
    statSync(join(dir, `${written}-fold-probe`));
    return true;
  } catch {
    return false;
  } finally {
    rmSync(p, { force: true });
  }
}

describe('hard links into credential stores (local)', () => {
  let home: string;
  let skill: string;
  let fs: HomeFS;

  beforeEach(() => {
    home = realpathSync(mkdtempSync(join(tmpdir(), 'hardlink-')));
    mkdirSync(join(home, '.ssh'));
    writeFileSync(join(home, '.ssh', 'id_rsa'), 'SSHKEYCANARY', { mode: 0o600 });
    mkdirSync(join(home, '.claude'));
    writeFileSync(join(home, '.claude', '.credentials.json'), '{"claudeAiOauth":{}}', { mode: 0o600 });
    writeFileSync(join(home, 'notes.txt'), 'ordinary');
    skill = join(home, '.claude', 'skills', 's');
    mkdirSync(skill, { recursive: true });
    writeFileSync(join(skill, 'SKILL.md'), '# s');
    linkSync(join(home, '.ssh', 'id_rsa'), join(skill, 'id.txt'));
    linkSync(join(home, '.claude', '.credentials.json'), join(skill, 'c.json'));
    linkSync(join(home, 'notes.txt'), join(skill, 'notes.md'));
    fs = new HomeFS(home);
  });

  afterEach(() => rmSync(home, { recursive: true, force: true }));

  it('names the store file a hard link is, and nothing for an ordinary one', async () => {
    expect(await fs.hardLinkOf(join(skill, 'id.txt'))).toBe(join(home, '.ssh', 'id_rsa'));
    expect(await fs.hardLinkOf(join(skill, 'c.json'))).toBe(join(home, '.claude', '.credentials.json'));
    expect(await fs.hardLinkOf(join(skill, 'notes.md'))).toBeUndefined();
    expect(await fs.hardLinkOf(join(skill, 'SKILL.md'))).toBeUndefined();
    // the store file under its own name is no link into a store
    expect(await hardLinkedSink(fs, join(home, '.ssh', 'id_rsa'))).toBeUndefined();
    expect(await new LocalHardLinkIndex(() => []).hardLinkOf(join(skill, 'id.txt'))).toBeUndefined();
  });

  it('leaves them out of the skill walk and the IOC file walk', async () => {
    const names = (await walkSkillTree(fs, join(home, '.claude', 'skills'))).map(e => e.name);
    expect(names).toContain('notes.md');
    expect(names).not.toContain('id.txt');
    expect(names).not.toContain('c.json');
    const cache = new Map<string, string>();
    expect(await skillFileInSink(fs, join(home, '.claude', 'skills'), join(skill, 'id.txt'), cache)).toBe(true);
    expect(await skillFileInSink(fs, join(home, '.claude', 'skills'), join(skill, 'notes.md'), cache)).toBe(false);
  });

  it('never reads a config that is one', async () => {
    linkSync(join(home, '.ssh', 'id_rsa'), join(home, '.claude', 'settings.json'));
    expect(await linkedIntoSink(join(home, '.claude', 'settings.json'), fs)).toBe(join(home, '.ssh', 'id_rsa'));
  });

  it('SKL-013 reports it as critical', async () => {
    const result = await skl013.run(ctxFor(fs, join(home, '.claude', 'skills')));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    const files = (result.evidence ?? []).map(e => e.file);
    expect(files).toEqual(expect.arrayContaining([join(skill, 'id.txt'), join(skill, 'c.json')]));
    expect(files).not.toContain(join(skill, 'notes.md'));
    expect(result.evidence?.find(e => e.file === join(skill, 'id.txt'))?.detail).toMatch(/^Hard link to SSH keys/);
  });

  it('SKL-013 reports a link into a store by where it really leads: a hop, a folded spelling', async () => {
    rmSync(join(skill, 'id.txt'));
    rmSync(join(skill, 'c.json'));
    symlinkSync('hop1', join(home, 'hop2'));
    symlinkSync('.ssh', join(home, 'hop1'));
    symlinkSync(join(home, 'hop2'), join(skill, 'd'));
    let result = await skl013.run(ctxFor(fs, join(home, '.claude', 'skills')));
    expect(result.severity).toBe('critical');
    if (!folds(home, '.ssh', '.ßh')) return;
    rmSync(join(skill, 'd'));
    symlinkSync(join(home, '.ßh'), join(skill, 'k'));
    result = await skl013.run(ctxFor(fs, join(home, '.claude', 'skills')));
    expect(result.severity).toBe('critical');
  });
});

describe('hard links into credential stores (snapshots)', () => {
  const home = '/home/u';
  const skill = `${home}/.claude/skills/s`;
  const snap = (extra: Partial<ProbeSnapshot> = {}) => new SnapshotFSProvider({
    version: 1, hostname: 'box', platform: 'linux', homedir: home, timestamp: '2026-11-16T00:00:00Z',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: {
      [`${skill}/SKILL.md`]: { content: '# s', mode: 0o644, exists: true },
      [`${skill}/id.txt`]: { content: '', mode: 0o600, exists: true, contentOmitted: true, omitted: 'sensitive', hardLinkOf: `${home}/.ssh/id_rsa` },
    },
    directories: {}, commandOutputs: {}, env: {}, directoryModes: {},
    ...extra,
  });

  it('answers what the probe recorded; SKL-013 and the walk judge it as locally', async () => {
    const fs = snap();
    expect(await fs.hardLinkOf(`${skill}/id.txt`)).toBe(`${home}/.ssh/id_rsa`);
    expect(await fs.hardLinkOf(`${skill}/SKILL.md`)).toBeUndefined();
    const result = await skl013.run(ctxFor(fs, `${home}/.claude/skills`));
    expect(result.severity).toBe('critical');
    const names = (await walkSkillTree(fs, `${home}/.claude/skills`)).map(e => e.name);
    expect(names).toContain('SKILL.md');
    expect(names).not.toContain('id.txt');
  });

  it('realpath takes a recorded respelling that only full case folding equates', async () => {
    const fs = snap({ symlinks: { [`${skill}/k`]: `${home}/.ßh` }, resolvedDirs: { [`${home}/.ßh`]: `${home}/.ssh` }, directories: { [`${home}/.ssh`]: [] } });
    expect(await fs.realpath(`${skill}/k`)).toBe(`${home}/.ssh`);
    expect(foldCase('weiß')).toBe(foldCase('WEISS'));
    expect(foldCase('ﬁx')).toBe(foldCase('fix'));
    expect(foldCase('café')).toBe(foldCase('CAFÉ'));
    expect(foldCase('.ssh')).not.toBe(foldCase('.ssx'));
  });
});

describe('sink classification folds like the probe', () => {
  it('classifies the long s and the Kelvin sign as their letters', () => {
    expect(classifySensitivePath('/home/u/.ſſh/id_rsa')).toHaveLength(1);
    expect(classifySensitivePath('/home/u/.Kube/config')).toHaveLength(1);
    expect(classifySensitivePath('/home/u/.ßh/id_rsa')).toEqual([]);
  });

  it('homeOfPath finds the user home a path lies in', () => {
    expect(homeOfPath('/Users/u/.claude/skills/x')).toBe('/Users/u');
    expect(homeOfPath('/home/u')).toBe('/home/u');
    expect(homeOfPath('/root/x')).toBe('/root');
    expect(homeOfPath('/opt/x')).toBeUndefined();
  });
});
