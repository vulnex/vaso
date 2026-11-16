import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LocalFSProvider } from './local-fs-provider.js';
import { SnapshotFSProvider } from './snapshot-fs-provider.js';
import { listSkillTree } from './utils.js';
import { linkCap, skillRootGap, unscannedReason, unscannedShortReason } from './skill-root-scope.js';
import { MAX_LINKED_SKILL_ENTRIES, MAX_SKILL_TREE_ENTRIES } from './skill-tree-count.js';
import { collectSkillInventory } from '../inventory/skills.js';
import { registerAllAdapters } from '../adapters/index.js';
import { adapterRegistry } from '../adapters/registry.js';
import type { AgentInstallation } from './types.js';
import type { ProbeSnapshot } from './snapshot-types.js';

/** A tree of exactly `n` entries under `dir`: pad/ and n-1 files in it. */
async function exactEntries(dir: string, n: number): Promise<void> {
  await mkdir(join(dir, 'pad'), { recursive: true });
  for (let i = 0; i < n - 1; i += 500) {
    await Promise.all(Array.from({ length: Math.min(500, n - 1 - i) }, (_, j) => writeFile(join(dir, 'pad', `${i + j}`), '')));
  }
}

/** A 9,999-entry tree holding one skill (s/SKILL.md). */
async function skillTree(dir: string): Promise<void> {
  await exactEntries(dir, MAX_SKILL_TREE_ENTRIES - 1 - 2);
  await mkdir(join(dir, 's'));
  await writeFile(join(dir, 's', 'SKILL.md'), '# s\n');
}

describe('links in a skills tree: each its own budget, a total for all', () => {
  let root: string;
  let out: string;
  let home: string;
  let fs: LocalFSProvider;

  beforeAll(async () => {
    if (adapterRegistry.getAdapters().length === 0) registerAllAdapters();
    root = await realpath(await mkdtemp(join(tmpdir(), 'vaso-link-plan-')));
    out = await realpath(await mkdtemp('/tmp/vaso-link-plan-out-'));
    home = join(root, 'home');
    await mkdir(join(home, '.claude'), { recursive: true });
    fs = Object.assign(Object.create(new LocalFSProvider()) as LocalFSProvider, { homedir: () => home });
    for (let i = 1; i <= 6; i++) await skillTree(join(out, `t${i}`));
  }, 180_000);
  afterAll(async () => {
    await rm(root, { recursive: true, force: true });
    await rm(out, { recursive: true, force: true });
  });

  it('links inside a linked root are not counted against it', async () => {
    // ~/.claude/skills → a profile holding a skill and links to two 9,999-entry trees
    const prof = join(out, 'profile');
    await mkdir(join(prof, 'ok'), { recursive: true });
    await writeFile(join(prof, 'ok', 'SKILL.md'), '# ok\n');
    await symlink(join(out, 't1'), join(prof, 'a'));
    await symlink(join(out, 't2'), join(prof, 'b'));
    const skills = join(home, '.claude', 'skills');
    await symlink(prof, skills);
    expect(await skillRootGap(fs, skills, home)).toBeUndefined();
    const listing = await listSkillTree(skills, fs);
    expect(listing.overLimitLinks).toEqual([]);
    expect(listing.overTotalLinks).toEqual([]);
    for (const f of ['ok/SKILL.md', 'a/s/SKILL.md', 'b/s/SKILL.md']) expect(listing.files).toContain(join(skills, f));
    await rm(skills);
  }, 60_000);

  it('past the links\' total, a link is left out and reported not scanned', async () => {
    const skills = join(home, 'plain-skills');
    await mkdir(skills);
    for (let i = 1; i <= 6; i++) await symlink(join(out, `t${i}`), join(skills, `l${i}`));
    const listing = await listSkillTree(skills, fs);
    expect(listing.overTotalLinks).toEqual([join(skills, 'l6')]);
    // the same tree outside the home (a config-set root elsewhere) holds to the same total
    const elsewhere = join(out, 'elsewhere');
    await mkdir(elsewhere);
    for (let i = 1; i <= 6; i++) await symlink(join(out, `t${i}`), join(elsewhere, `l${i}`));
    expect((await listSkillTree(elsewhere, fs)).overTotalLinks).toEqual([join(elsewhere, 'l6')]);
    expect(listing.overLimitLinks).toEqual([]);
    for (let i = 1; i <= 5; i++) expect(listing.files).toContain(join(skills, `l${i}`, 's', 'SKILL.md'));
    expect(listing.files.some(f => f.startsWith(join(skills, 'l6') + '/'))).toBe(false);

    const inst: AgentInstallation = { agent: 'claude-code', installDir: join(home, '.claude'), configFiles: [], skillsDir: skills };
    const { inventory } = await collectSkillInventory(inst, fs);
    expect(inst.unscannedSkillsDirs).toEqual([{ path: join(skills, 'l6'), reason: 'total' }]);
    expect(inventory.incomplete?.join('\n')).toContain(`${join(skills, 'l6')}: ${unscannedReason('total', join(skills, 'l6'))}`);
    expect(unscannedReason('total', '/x')).toBe(`not scanned: linked skills directory past the ${MAX_LINKED_SKILL_ENTRIES}-entry total VASO walks through the links of one skills tree (locally or remotely) — not verified; review it with \`vaso skill audit /x\``);
    expect(unscannedShortReason({ reason: 'total' })).toBe('past the 50000-entry total for linked trees');
  }, 60_000);

  it('many links to one tree over the limit count it once', async () => {
    const big = join(out, 'big');
    await exactEntries(big, MAX_SKILL_TREE_ENTRIES + 1);
    const skills = join(home, 'many');
    await mkdir(skills);
    for (let i = 0; i < 200; i++) await symlink(big, join(skills, `l${String(i).padStart(3, '0')}`));
    const start = Date.now();
    const listing = await listSkillTree(skills, fs);
    expect(Date.now() - start).toBeLessThan(5000);
    expect(listing.overLimitLinks).toHaveLength(200);
  }, 60_000);
});

describe('links left out on a snapshot', () => {
  const snapshot = (over: Partial<ProbeSnapshot>): ProbeSnapshot => ({
    version: 1, hostname: 'h', platform: 'linux', homedir: '/home/u', timestamp: '2026-11-16T00:00:00Z',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: { '/home/u/.claude/skills/kept/s/SKILL.md': { content: '# s', mode: 0o100644, exists: true } },
    directories: {}, commandOutputs: {}, env: {},
    ...over,
  });

  it('what the probe recorded decides; past its record bound a link with nothing under it is not verified', async () => {
    const recorded = new SnapshotFSProvider(snapshot({ configTrees: { '/home/u/.claude/skills/big': 'limit', '/home/u/.claude/skills/late': 'total' } }));
    let cap = await linkCap(recorded, '/home/u/.claude/skills');
    expect(await cap('/home/u/.claude/skills/big')).toBe('limit');
    expect(await cap('/home/u/.claude/skills/late')).toBe('total');
    expect(await cap('/home/u/.claude/skills/other')).toBeUndefined();
    const truncated = new SnapshotFSProvider(snapshot({ skillLinksTruncated: true }));
    cap = await linkCap(truncated, '/home/u/.claude/skills');
    expect(await cap('/home/u/.claude/skills/other')).toBe('limit');
    expect(await cap('/home/u/.claude/skills/kept')).toBeUndefined();
  });
});
