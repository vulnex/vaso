import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalFSProvider } from './local-fs-provider.js';
import type { DirentInfo, FSProvider } from './fs-provider.js';
import { MAX_JUDGED_LINK_ENTRIES, MAX_LINKED_SKILL_ENTRIES, MAX_SKILL_TREE_ENTRIES, countSkillTreeEntries, planSkillLinks, scanSkillTree } from './skill-tree-count.js';
import type { TreeScan } from './skill-tree-count.js';
import { overEntryLimit, skillRootGap, unscannedReason, unscannedShortReason } from './skill-root-scope.js';
import { screenDefaultSkillRoots } from '../adapters/default-skill-roots.js';
import { registerAllAdapters } from '../adapters/index.js';
import { adapterRegistry } from '../adapters/registry.js';

const fs = new LocalFSProvider();
const always = async () => true;

/** `n` empty files in `dir`. */
async function fill(dir: string, n: number): Promise<void> {
  await mkdir(dir, { recursive: true });
  await Promise.all(Array.from({ length: n }, (_, i) => writeFile(join(dir, `f${i}`), '')));
}

describe('skill tree entry count', () => {
  let root: string;
  beforeAll(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-count-')));
  });
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('shares the probe\'s limit', () => {
    expect(MAX_SKILL_TREE_ENTRIES).toBe(10000);
  });

  it('counts files and directories below the root, not the root, skipping vendor dirs but not build output', async () => {
    const t = join(root, 'plain');
    await fill(join(t, 'a'), 3); // a + 3
    await fill(join(t, 'a', 'dist'), 2); // dist + 2
    await fill(join(t, 'node_modules', 'x'), 50); // skipped whole
    await fill(join(t, '.git'), 5); // skipped whole
    await writeFile(join(t, 'SKILL.md'), '');
    expect(await countSkillTreeEntries(fs, t, 100)).toBe(1 + 3 + 1 + 2 + 1);
  });

  it('a tree of exactly the limit is within it; one more entry is over', async () => {
    const at = join(root, 'at');
    await fill(at, MAX_SKILL_TREE_ENTRIES);
    expect(await countSkillTreeEntries(fs, at, MAX_SKILL_TREE_ENTRIES)).toBe(MAX_SKILL_TREE_ENTRIES);
    expect(await overEntryLimit(fs, at)).toBe(false);
    const over = join(root, 'over');
    await fill(over, MAX_SKILL_TREE_ENTRIES + 1);
    expect(await countSkillTreeEntries(fs, over, MAX_SKILL_TREE_ENTRIES)).toBe(MAX_SKILL_TREE_ENTRIES + 1);
    expect(await overEntryLimit(fs, over)).toBe(true);
  });

  it('stops listing once past the limit', async () => {
    const listed: string[] = [];
    const counting: FSProvider = Object.assign(Object.create(fs) as LocalFSProvider, {
      readdirEntries: (p: string): Promise<DirentInfo[]> => {
        listed.push(p);
        return fs.readdirEntries(p);
      },
    });
    const t = join(root, 'many');
    for (let d = 0; d < 20; d++) await fill(join(t, `d${String(d).padStart(2, '0')}`), 10);
    expect(await countSkillTreeEntries(counting, t, 25)).toBe(26);
    // d00 (11 entries), d01 (11), then d02's 4th entry: three directories listed past the root
    expect(listed.length).toBe(4);
  });

  it('counts from where a linked root leads; a link counts as one entry, never descended into', async () => {
    const target = join(root, 'target');
    await fill(join(target, 's'), 4); // s + 4
    const shared = join(root, 'shared');
    await fill(shared, 3);
    await symlink(shared, join(target, 'l1'));
    await symlink(target, join(target, 's', 'back'));
    await symlink(join(root, 'missing'), join(target, 'dangling'));
    const link = join(root, 'linked-root');
    await symlink(target, link);
    const expected = 5 + 1 + 1 + 1;
    expect(await countSkillTreeEntries(fs, link, 1000)).toBe(expected);
    const scan = await scanSkillTree(fs, target, 1000);
    expect(scan.n).toBe(expected);
    // in WalkDir order, under the tree's real path
    expect(scan.links).toEqual([join(target, 'dangling'), join(target, 'l1'), join(target, 's', 'back')]);
  });

  it('an unreadable directory counts as itself', async () => {
    const t = join(root, 'gone');
    await mkdir(t, { recursive: true });
    await writeFile(join(t, 'x'), '');
    const flaky: FSProvider = Object.assign(Object.create(fs) as LocalFSProvider, {
      readdirEntries: (p: string): Promise<DirentInfo[]> => (p === t ? fs.readdirEntries(p) : Promise.reject(new Error('EACCES'))),
    });
    expect(await countSkillTreeEntries(flaky, t, 10)).toBe(1);
    expect(await countSkillTreeEntries(fs, join(root, 'nope'), 10)).toBe(0);
  });
});

describe('link plan of a skills tree', () => {
  let root: string;
  const scans = new Map<string, Promise<TreeScan>>();
  const scanOf = (real: string) => {
    let s = scans.get(real);
    if (!s) scans.set(real, (s = scanSkillTree(fs, real, MAX_SKILL_TREE_ENTRIES)));
    return s;
  };
  beforeAll(async () => {
    root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-plan-')));
  });
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it('judges each link from its own target and charges the links\' total', async () => {
    expect(MAX_LINKED_SKILL_ENTRIES).toBe(5 * MAX_SKILL_TREE_ENTRIES);
    const tree = join(root, 'tree');
    await fill(join(tree, 'own'), 20);
    const targets: string[] = [];
    for (let i = 1; i <= 6; i++) {
      const t = join(root, `t${i}`);
      await fill(join(t, 'pad'), MAX_SKILL_TREE_ENTRIES - 1); // 10,000 entries: at the limit
      targets.push(t);
      await symlink(t, join(tree, `l${i}`));
    }
    const big = join(root, 'big');
    await fill(join(big, 'pad'), MAX_SKILL_TREE_ENTRIES);
    await symlink(big, join(tree, 'a-big'));
    await symlink(targets[0], join(tree, 'z-again'));
    // a-big over the limit is never walked: not charged; l1–l5 (50,000), l6 past it
    const plan = await planSkillLinks(fs, tree, always, scanOf);
    expect(plan.get(big)).toBe('limit');
    expect(targets.map(t => plan.get(t))).toEqual(['follow', 'follow', 'follow', 'follow', 'follow', 'total']);
    expect(plan.size).toBe(7);
  }, 120_000);

  it('charges the total only with what it follows, and counts a bounded amount to judge links', async () => {
    const tree = join(root, 'judged');
    const sizes = new Map<string, number>();
    const fake = async (real: string): Promise<TreeScan> => ({ n: sizes.get(real) ?? 0, links: [] });
    const link = async (name: string, n: number) => {
      const t = join(root, `j-${name}`);
      await mkdir(t, { recursive: true });
      await symlink(t, join(tree, name));
      sizes.set(t, n);
      return t;
    };
    await mkdir(tree);
    const bigs: string[] = [];
    for (let i = 0; i < 51; i++) bigs.push(await link(`b${String(i).padStart(2, '0')}`, MAX_SKILL_TREE_ENTRIES + 1));
    const plan = await planSkillLinks(fs, tree, always, fake);
    // fifty targets at the limit fill what judging may count: the 51st is not counted
    expect(bigs.slice(0, 50).every(b => plan.get(b) === 'limit')).toBe(true);
    expect(plan.get(bigs[50])).toBe('total');
    expect(MAX_JUDGED_LINK_ENTRIES).toBe(10 * MAX_LINKED_SKILL_ENTRIES);

    // a link past the total isn't charged either: a later small one still fits
    const tree2 = join(root, 'fits');
    await mkdir(tree2);
    const t2 = async (name: string, n: number) => {
      const t = join(root, `f-${name}`);
      await mkdir(t, { recursive: true });
      await symlink(t, join(tree2, name));
      sizes.set(t, n);
      return t;
    };
    const ts = [];
    for (const [name, n] of [['a', 10000], ['b', 10000], ['c', 10000], ['d', 10000], ['e', 9999], ['f', 5000], ['g', 1]] as const) ts.push(await t2(name, n));
    const plan2 = await planSkillLinks(fs, tree2, always, fake);
    expect(ts.map(t => plan2.get(t))).toEqual(['follow', 'follow', 'follow', 'follow', 'follow', 'total', 'follow']);
  });

  it('takes a followed link\'s own links right after it, not into a tree already taken nor above the root', async () => {
    const tree = join(root, 'nest');
    const outer = join(root, 'outer');
    const inner = join(root, 'inner');
    await fill(join(outer, 's'), 2);
    await fill(inner, 2);
    await symlink(inner, join(outer, 'in'));
    await symlink(join(outer, 's'), join(outer, 'back'));
    await mkdir(tree);
    await symlink(outer, join(tree, 'out'));
    await symlink(root, join(tree, 'up'));
    const plan = await planSkillLinks(fs, tree, always, scanOf);
    expect([...plan.entries()]).toEqual([[outer, 'follow'], [inner, 'follow']]);
    // a link the scope refuses gets no verdict
    const refused = await planSkillLinks(fs, tree, async p => !p.endsWith('/in'), scanOf);
    expect([...refused.keys()]).toEqual([outer]);
  });

  it('follows links at most eight deep', async () => {
    const base = join(root, 'chain');
    await mkdir(base, { recursive: true });
    const dirs = Array.from({ length: 12 }, (_, i) => join(root, `hop${i}`));
    for (const [i, d] of dirs.entries()) {
      await mkdir(d, { recursive: true });
      await writeFile(join(d, 'f'), '');
      if (i + 1 < dirs.length) await symlink(dirs[i + 1], join(d, 'next'));
    }
    await symlink(dirs[0], join(base, 'next'));
    const plan = await planSkillLinks(fs, base, always, scanOf);
    expect(plan.size).toBe(8);
  });
});

describe('skills trees over the entry limit (local scans)', () => {
  let root: string;
  let home: string;
  let out: string;
  const local = () => Object.assign(Object.create(fs) as LocalFSProvider, { homedir: () => home });

  beforeAll(async () => {
    if (adapterRegistry.getAdapters().length === 0) registerAllAdapters();
    root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-limit-')));
    // out of the test home, where a skills tree may be walked (not under /var)
    out = await realpath(await mkdtemp('/tmp/vaso-limit-out-'));
    home = join(root, 'home');
    await fill(join(out, 'big', 'pad'), MAX_SKILL_TREE_ENTRIES);
    await fill(join(out, 'small'), 10);
    await mkdir(join(home, '.claude'), { recursive: true });
    await symlink(join(out, 'big'), join(home, 'big-link'));
    await fill(join(home, 'plain-big', 'pad'), MAX_SKILL_TREE_ENTRIES);
    await mkdir(join(home, '.picoclaw'), { recursive: true });
    await fill(join(out, 'bigws', 'skills', 'pad'), MAX_SKILL_TREE_ENTRIES);
    await fill(join(out, 'smallws', 'skills'), 3);
    await symlink(join(out, 'bigws'), join(home, '.picoclaw', 'workspace-big'));
    await symlink(join(out, 'smallws'), join(home, '.picoclaw', 'workspace-small'));
  }, 60_000);
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
    await rm(out, { recursive: true, force: true });
  });

  it('a config-set directory over the limit, as written or through a link, is not scanned', async () => {
    expect(await skillRootGap(local(), join(out, 'big'), home)).toBe('limit');
    expect(await skillRootGap(local(), join(home, 'big-link'), home)).toBe('limit');
    expect(await skillRootGap(local(), join(home, 'plain-big'), home)).toBe('limit');
    expect(await skillRootGap(local(), join(out, 'small'), home)).toBeUndefined();
  });

  it('an agent\'s own skills directory: capped when a link takes it elsewhere, walked whatever it holds otherwise', async () => {
    await rm(join(home, '.claude', 'skills'), { recursive: true, force: true });
    await symlink(join(out, 'big'), join(home, '.claude', 'skills'));
    expect(await skillRootGap(local(), join(home, '.claude', 'skills'), home)).toBe('limit');
    // a linked wildcard directory (PicoClaw workspace-<id>): its skills tree is capped
    expect(await skillRootGap(local(), join(home, '.picoclaw', 'workspace-big', 'skills'), home)).toBe('limit');
    expect(await skillRootGap(local(), join(home, '.picoclaw', 'workspace-small', 'skills'), home)).toBeUndefined();
    // a plain directory in the home: the probe walks it as a manifest tree, uncapped
    await rm(join(home, '.claude', 'skills'));
    await fill(join(home, '.claude', 'skills', 'pad'), MAX_SKILL_TREE_ENTRIES + 5);
    expect(await skillRootGap(local(), join(home, '.claude', 'skills'), home)).toBeUndefined();
  }, 60_000);

  it('moves a capped default directory to the not-scanned list with a neutral reason', async () => {
    await rm(join(home, '.claude', 'skills'), { recursive: true, force: true });
    await symlink(join(out, 'big'), join(home, '.claude', 'skills'));
    const dir = join(home, '.claude', 'skills');
    const [inst] = await screenDefaultSkillRoots([{ agent: 'claude-code', installDir: join(home, '.claude'), configFiles: [], skillsDir: dir }], local());
    expect(inst.skillsDirs).toEqual([]);
    expect(inst.unscannedSkillsDirs).toEqual([{ path: dir, reason: 'limit', agentDefault: true }]);
    const reason = unscannedReason('limit', dir);
    expect(reason).toBe(`not scanned: skills directory holds more than 10000 entries, over the limit VASO walks in a skills tree (locally or remotely) — not verified; review it with \`vaso skill audit ${dir}\``);
    expect(reason).not.toMatch(/remote probe/);
    expect(unscannedShortReason({ reason: 'limit' })).toBe('over the 10000-entry limit');
    // a snapshot's link the probe no longer recorded: not "over the limit"
    expect(unscannedShortReason({ reason: 'truncated' })).toBe('not verified: the remote probe stopped recording links after 20000');
    expect(unscannedReason('truncated', dir)).toContain('stopped recording links it does not follow (after 20000) — not verified');
  });

  it('decides a huge tree fast', async () => {
    const huge = join(out, 'huge');
    for (let d = 0; d < 40; d++) await fill(join(huge, `d${d}`), 1000);
    const start = Date.now();
    expect(await skillRootGap(local(), huge, home)).toBe('limit');
    expect(Date.now() - start).toBeLessThan(5000);
  }, 120_000);
});
