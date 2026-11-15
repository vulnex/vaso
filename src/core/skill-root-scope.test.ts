import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalFSProvider } from './local-fs-provider.js';
import { inHomeOutsideStores, screenSkillRoots, unscannedReason } from './skill-root-scope.js';
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
