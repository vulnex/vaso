import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalFSProvider } from './local-fs-provider.js';
import { homeOfDir, inHomeOutsideStores, screenSkillRoots, skillRootGap, unscannedReason } from './skill-root-scope.js';
import { screenDefaultSkillRoots } from '../adapters/default-skill-roots.js';
import { registerAllAdapters } from '../adapters/index.js';
import { adapterRegistry } from '../adapters/registry.js';

describe('config-set skill roots (local scans)', () => {
  let root: string;
  let home: string;
  const fs = new LocalFSProvider();

  beforeAll(async () => {
    if (adapterRegistry.getAdapters().length === 0) registerAllAdapters();
    root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-scope-')));
    home = join(root, 'home');
    await mkdir(join(home, 'work', 'skills'), { recursive: true });
    await mkdir(join(root, 'other', 'skills'), { recursive: true });
    await writeFile(join(home, 'work', 'skills', 'SKILL.md'), '# x\n');
    await symlink(join(root, 'other'), join(home, 'to-other'));
    await symlink('/etc', join(home, 'to-etc'));
    await mkdir(join(home, '.config', 'gh'), { recursive: true });
    await symlink(join(home, '.config', 'gh'), join(home, 'to-gh'));
  });
  afterAll(async () => rm(root, { recursive: true, force: true }));

  it('walks only strictly inside the home and outside credential stores, as written and resolved', async () => {
    const cases: Array<[string, boolean]> = [
      [join(home, 'work', 'skills'), true],
      [join(home, 'not-yet', 'skills'), true],
      [home, false],
      [root, false],
      ['/', false],
      ['/etc', false],
      ['/private/etc', false],
      [join(root, 'other', 'skills'), false],
      [join(home, 'to-other', 'skills'), false],
      [join(home, 'to-etc'), false],
      [join(home, 'to-gh'), false],
      [join(home, '.ssh'), false],
      [join(home, '.config', 'gcloud'), false],
      [join(home, 'Library', 'Keychains'), false],
      [join(home, 'work', '..', '..'), false],
    ];
    for (const [p, want] of cases) expect(await inHomeOutsideStores(fs, p, home), p).toBe(want);
  });

  it('reports what it leaves, with the reason', async () => {
    const { scan, unscanned } = await screenSkillRoots(fs, [join(home, 'work', 'skills'), '/', 'rel'], home);
    expect(scan).toEqual([join(home, 'work', 'skills')]);
    expect(unscanned).toEqual([{ path: '/', reason: 'outside' }, { path: 'rel', reason: 'relative' }]);
    expect(unscannedReason('outside')).toMatch(/^not scanned: /);
  });

  it('names the home directory itself as its own reason, as written or through a link', async () => {
    await symlink(home, join(root, 'home-link'));
    const { unscanned } = await screenSkillRoots(fs, [home, `${home}/`, join(root, 'home-link'), join(home, 'work', '..')], home);
    expect(unscanned.map(u => u.reason)).toEqual(['home', 'home', 'home', 'home']);
    expect(unscannedReason('home')).toMatch(/home directory itself/);
  });
});

describe('a linked home and linked default skill roots (local scans)', () => {
  let root: string;
  let home: string;
  const fs = new LocalFSProvider();

  beforeAll(async () => {
    if (adapterRegistry.getAdapters().length === 0) registerAllAdapters();
    root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-scope-link-')));
    home = join(root, 'real-home');
    await mkdir(join(home, 'ws', 'skills'), { recursive: true });
    await mkdir(join(home, '.ssh'), { recursive: true });
    await mkdir(join(root, 'outside', 'ws', 'skills'), { recursive: true });
    await symlink(home, join(root, 'link-home'));
    await mkdir(join(home, '.picoclaw'), { recursive: true });
    await symlink(join(root, 'outside', 'ws'), join(home, '.picoclaw', 'workspace-out'));
    await symlink(join(home, '.ssh'), join(home, '.picoclaw', 'workspace-ssh'));
    await symlink(join(home, 'ws'), join(home, '.picoclaw', 'workspace-in'));
    await symlink(home, join(home, '.picoclaw', 'workspace-home'));
  });
  afterAll(async () => rm(root, { recursive: true, force: true }));

  it('takes either spelling of a linked home for the home', async () => {
    const linkHome = join(root, 'link-home');
    expect(await inHomeOutsideStores(fs, join(home, 'ws', 'skills'), linkHome)).toBe(true);
    expect(await inHomeOutsideStores(fs, join(linkHome, 'ws', 'skills'), home)).toBe(true);
    expect(await inHomeOutsideStores(fs, join(linkHome, '.ssh'), home)).toBe(false);
    expect(await inHomeOutsideStores(fs, join(root, 'outside', 'ws'), linkHome)).toBe(false);
    expect(await homeOfDir(fs, join(linkHome, 'ws'), [home])).toBe(home);
    expect(await homeOfDir(fs, join(root, 'outside'), [home])).toBeUndefined();
  });

  it('refuses an agent\'s own skills directory linked out of the home or into a store', async () => {
    const pc = join(home, '.picoclaw');
    expect(await skillRootGap(fs, join(pc, 'workspace-out', 'skills'), home)).toBe('outside');
    expect(await skillRootGap(fs, join(pc, 'workspace-ssh', 'skills'), home)).toBe('outside');
    expect(await skillRootGap(fs, join(pc, 'workspace-home', 'skills'), home)).toBeUndefined(); // ~/skills: inside
    expect(await skillRootGap(fs, join(pc, 'workspace-in', 'skills'), home)).toBeUndefined();
    expect(await skillRootGap(fs, join(pc, 'workspace-home'), home)).toBe('home');
  });

  it('moves them to the not-scanned list of the installation', async () => {
    const pc = join(home, '.picoclaw');
    const dirs = ['out', 'ssh', 'in'].map(n => join(pc, `workspace-${n}`, 'skills'));
    const [inst] = await screenDefaultSkillRoots([{
      agent: 'picoclaw', installDir: pc, configFiles: [], skillsDir: dirs[0], skillsDirs: [...dirs, join(root, 'outside', 'ws', 'skills')],
    }], Object.assign(Object.create(fs) as LocalFSProvider, { homedir: () => home }));
    expect(inst.skillsDirs).toEqual([dirs[2], join(root, 'outside', 'ws', 'skills')]);
    expect(inst.skillsDir).toBe(dirs[2]);
    expect(inst.unscannedSkillsDirs).toEqual([{ path: dirs[0], reason: 'outside' }, { path: dirs[1], reason: 'outside' }]);
  });
});
