import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { LocalFSProvider } from './local-fs-provider.js';
import {
  homeOfDir, scopeLabels, screenSkillRoots, skillRootGap, skillTreeAllowed, unscannedReason, unscannedShortReason,
} from './skill-root-scope.js';
import { screenDefaultSkillRoots } from '../adapters/default-skill-roots.js';
import { registerAllAdapters } from '../adapters/index.js';
import { adapterRegistry } from '../adapters/registry.js';

/**
 * A directory out of the test home where a skills tree may be walked: under
 * /tmp (os.tmpdir() is under /var on macOS, an OS directory no skills tree
 * is walked in).
 */
async function allowedOutside(): Promise<string> {
  return realpath(await mkdtemp('/tmp/vaso-scope-out-'));
}

describe('scope labels (shared with the probe)', () => {
  it('label every path of probe/testdata/skill-scope-cases.json as the probe does', async () => {
    const cases = JSON.parse(await readFile(resolve(import.meta.dirname, '../../probe/testdata/skill-scope-cases.json'), 'utf-8')) as
      Array<{ path: string; own: string[]; all: string[]; labels: string[] }>;
    expect(cases.length).toBeGreaterThanOrEqual(30);
    for (const c of cases) expect(scopeLabels(c.path, c.own, c.all), `${c.path} own=${c.own} all=${c.all}`).toEqual(c.labels);
  });
});

describe('config-set skill roots (local scans)', () => {
  let root: string;
  let home: string;
  let other: string;
  const fs = new LocalFSProvider();

  beforeAll(async () => {
    if (adapterRegistry.getAdapters().length === 0) registerAllAdapters();
    root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-scope-')));
    other = await allowedOutside();
    home = join(root, 'home');
    await mkdir(join(home, 'work', 'skills'), { recursive: true });
    await mkdir(join(other, 'skills'), { recursive: true });
    await writeFile(join(home, 'work', 'skills', 'SKILL.md'), '# x\n');
    await symlink(other, join(home, 'to-other'));
    await symlink('/etc', join(home, 'to-etc'));
    await symlink('/usr/share', join(home, 'to-usr'));
    await mkdir(join(home, '.config', 'gh'), { recursive: true });
    await mkdir(join(home, '.ssh'), { recursive: true });
    await symlink(join(home, '.config', 'gh'), join(home, 'to-gh'));
    await symlink(join(home, '.ssh'), join(other, 'to-ssh'));
  });
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
    await rm(other, { recursive: true, force: true });
  });

  it('walks anywhere but the root, the home or above, other homes, OS directories and credential stores, as written and resolved', async () => {
    const cases: Array<[string, boolean]> = [
      [join(home, 'work', 'skills'), true],
      [join(home, 'not-yet', 'skills'), true],
      [join(other, 'skills'), true],
      [join(home, 'to-other', 'skills'), true],
      ['/opt/team-skills', true],
      ['/srv/skills', true],
      ['/nix/store/abc-hm/skills', true],
      ['/Volumes/Team/skills', true],
      ['/mnt/data/skills', true],
      ['/media/usb/skills', true],
      [home, false],
      [root, false],
      ['/', false],
      ['/etc', false],
      ['/private/etc', false],
      ['/usr/share', false],
      ['/var/lib/skills', false],
      ['/System/Library', false],
      ['/home', false],
      ['/home/someone-else/skills', false],
      ['/Users/someone-else/skills', false],
      ['/root/skills', false],
      [join(home, 'to-etc'), false],
      [join(home, 'to-usr'), false],
      [join(home, 'to-gh'), false],
      [join(other, 'to-ssh'), false],
      [join(home, '.ssh'), false],
      [join(home, '.config', 'gcloud'), false],
      [join(home, 'Library', 'Keychains'), false],
      [join(home, 'work', '..', '..'), false],
    ];
    for (const [p, want] of cases) expect(await skillTreeAllowed(fs, p, home), p).toBe(want);
  });

  it('reports what it leaves, with the reason and the kind of place', async () => {
    const { scan, unscanned } = await screenSkillRoots(fs, [join(home, 'work', 'skills'), '/', '/usr/local/skills', join(home, 'to-etc', 'x'), 'rel'], home);
    expect(scan).toEqual([join(home, 'work', 'skills')]);
    expect(unscanned).toEqual([
      { path: '/', reason: 'outside', refusedAs: 'the filesystem root' },
      { path: '/usr/local/skills', reason: 'outside', refusedAs: 'an OS directory (/usr)' },
      // named by where its link leads (as written: /etc, not the OS's /private/etc)
      { path: join(home, 'to-etc', 'x'), reason: 'outside', target: '/etc/x', refusedAs: 'an OS directory (/etc)' },
      { path: 'rel', reason: 'relative' },
    ]);
    expect(unscannedReason('outside', '/usr/local/skills', unscanned[1])).toBe(
      'not scanned: skills directory set to an OS directory (/usr) — VASO doesn\'t walk it (locally or remotely); keep skills in a dedicated folder');
    expect(unscannedReason('outside', unscanned[2].path, unscanned[2])).toMatch(/^not scanned: skills directory links to \/etc\/x, an OS directory \(\/etc\) — /);
    expect(unscannedShortReason(unscanned[2])).toBe('links to /etc/x, an OS directory (/etc)');
    expect(unscannedReason('outside')).toMatch(/^not scanned: skills directory set to an OS directory, another user's home or a credential store/);
  });

  it('names the home directory itself as its own reason, as written or through a link', async () => {
    await symlink(home, join(root, 'home-link'));
    const { unscanned } = await screenSkillRoots(fs, [home, `${home}/`, join(root, 'home-link'), join(home, 'work', '..')], home);
    // `<home>/` and `<home>/work/..` are the home, written another way: one entry
    expect(unscanned.map(u => [u.path, u.reason])).toEqual([[home, 'home'], [join(root, 'home-link'), 'home']]);
    expect(unscannedReason('home')).toMatch(/home directory itself/);
  });
});

describe('a linked home and linked default skill roots (local scans)', () => {
  let root: string;
  let home: string;
  let outside: string;
  const fs = new LocalFSProvider();

  beforeAll(async () => {
    if (adapterRegistry.getAdapters().length === 0) registerAllAdapters();
    root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-scope-link-')));
    outside = await allowedOutside();
    home = join(root, 'real-home');
    await mkdir(join(home, 'ws', 'skills'), { recursive: true });
    await mkdir(join(home, '.ssh'), { recursive: true });
    await mkdir(join(outside, 'ws', 'skills'), { recursive: true });
    await symlink(home, join(root, 'link-home'));
    await mkdir(join(home, '.picoclaw'), { recursive: true });
    await symlink(join(outside, 'ws'), join(home, '.picoclaw', 'workspace-out'));
    await symlink(join(home, '.ssh'), join(home, '.picoclaw', 'workspace-ssh'));
    await symlink(join(home, 'ws'), join(home, '.picoclaw', 'workspace-in'));
    await symlink(home, join(home, '.picoclaw', 'workspace-home'));
    await mkdir(join(home, 'etcws'), { recursive: true });
    await symlink('/etc', join(home, 'etcws', 'skills'));
    await symlink(join(home, 'etcws'), join(home, '.picoclaw', 'workspace-etc'));
    await mkdir(join(outside, 'vol', 'claude', 'skills'), { recursive: true });
    await symlink(join(outside, 'vol', 'claude'), join(home, '.claude'));
  });
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  });

  it('takes either spelling of a linked home for the home', async () => {
    const linkHome = join(root, 'link-home');
    expect(await skillTreeAllowed(fs, join(home, 'ws', 'skills'), linkHome)).toBe(true);
    expect(await skillTreeAllowed(fs, join(linkHome, 'ws', 'skills'), home)).toBe(true);
    expect(await skillTreeAllowed(fs, join(linkHome, '.ssh'), home)).toBe(false);
    expect(await skillTreeAllowed(fs, linkHome, home)).toBe(false);
    expect(await homeOfDir(fs, join(linkHome, 'ws'), [home])).toBe(home);
    expect(await homeOfDir(fs, join(outside, 'ws'), [home])).toBeUndefined();
  });

  it('walks an agent\'s own skills directory linked out of the home; refuses one linked into a store, an OS directory or the home', async () => {
    const pc = join(home, '.picoclaw');
    expect(await skillRootGap(fs, join(pc, 'workspace-out', 'skills'), home)).toBeUndefined();
    expect(await skillRootGap(fs, join(home, '.claude', 'skills'), home)).toBeUndefined(); // ~/.claude on another volume
    expect(await skillRootGap(fs, join(pc, 'workspace-ssh', 'skills'), home)).toBe('outside');
    expect(await skillRootGap(fs, join(pc, 'workspace-etc', 'skills'), home)).toBe('outside');
    expect(await skillRootGap(fs, join(pc, 'workspace-home', 'skills'), home)).toBeUndefined(); // ~/skills: inside
    expect(await skillRootGap(fs, join(pc, 'workspace-in', 'skills'), home)).toBeUndefined();
    expect(await skillRootGap(fs, join(pc, 'workspace-home'), home)).toBe('home');
  });

  it('moves the refused ones to the not-scanned list, naming where they lead', async () => {
    const pc = join(home, '.picoclaw');
    const dirs = ['out', 'ssh', 'in', 'etc'].map(n => join(pc, `workspace-${n}`, 'skills'));
    const etcTarget = await realpath('/etc');
    const [inst] = await screenDefaultSkillRoots([{
      agent: 'picoclaw', installDir: pc, configFiles: [], skillsDir: dirs[1], skillsDirs: [...dirs, join(outside, 'ws', 'skills')],
    }], Object.assign(Object.create(fs) as LocalFSProvider, { homedir: () => home }));
    expect(inst.skillsDirs).toEqual([dirs[0], dirs[2], join(outside, 'ws', 'skills')]);
    expect(inst.skillsDir).toBe(dirs[0]);
    expect(inst.unscannedSkillsDirs).toEqual([
      { path: dirs[1], reason: 'outside', target: join(home, '.ssh', 'skills'), refusedAs: 'a credential store or sensitive location (SSH keys/config (~/.ssh))', agentDefault: true },
      // a link to /etc itself: macOS's own /etc → /private/etc is followed too, as the probe records it
      { path: dirs[3], reason: 'outside', target: etcTarget, refusedAs: 'an OS directory (/etc)', agentDefault: true },
    ]);
    expect(unscannedReason('outside', dirs[3], inst.unscannedSkillsDirs![1])).toBe(
      `not scanned: skills directory links to ${etcTarget}, an OS directory (/etc) — VASO doesn't walk it (locally or remotely); keep skills in a dedicated folder`);
  });
});
