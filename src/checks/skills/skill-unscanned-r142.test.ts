import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { chmod, mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { AgentInstallation, ScanContext } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { SnapshotFSProvider } from '../../core/snapshot-fs-provider.js';
import { listSkillTree } from '../../core/utils.js';
import { collectSkillInventory } from '../../inventory/skills.js';
import { MAX_SCAN_FILE_BYTES } from '../../core/file-limits.js';
import { skl002 } from './skl-002-obfuscated-code.js';
import { skl003 } from './skl-003-eval-exec.js';

// A folder inside a skill that can't be listed, and a skill file padded past
// the content-scan limit, hid the skill's code from every check while SKL-002
// passed (or reported an info). Both are "not scanned" warnings now, locally
// and from a probe snapshot.

const installation = (skillsDir: string): AgentInstallation => ({ agent: 'claude-code', installDir: skillsDir, configFiles: [], skillsDir });
const ctxOf = (skillsDir: string, fs: FSProvider): ScanContext => ({ installation: installation(skillsDir), configs: [], platform: 'linux', fs });
/** A context as the engine builds it: the inventory walk's files and unlistable folders. */
async function engineCtx(skillsDir: string, fs: FSProvider): Promise<ScanContext> {
  const inst = installation(skillsDir);
  const { files, unlistableDirs } = await collectSkillInventory(inst, fs);
  return { installation: inst, configs: [], platform: 'linux', fs, skillFiles: files, skillUnlistableDirs: unlistableDirs };
}

describe.skipIf(process.platform === 'win32' || process.getuid?.() === 0)('a folder inside a skill that cannot be listed (local)', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'vaso-r142-'));
    await mkdir(join(dir, 's2', 'locked'), { recursive: true });
    await mkdir(join(dir, 's2', 'empty'));
    await writeFile(join(dir, 's2', 'SKILL.md'), '---\nname: s2\n---\n# s2\n');
    await writeFile(join(dir, 's2', 'locked', 'a.js'), 'eval(process.argv[2]);\n');
    await chmod(join(dir, 's2', 'locked'), 0o000);
  });
  afterEach(async () => {
    await chmod(join(dir, 's2', 'locked'), 0o755).catch(() => {});
    await rm(dir, { recursive: true, force: true });
  });

  it('the walk lists it (not an empty folder, not the skill itself)', async () => {
    const listing = await listSkillTree(dir, new LocalFSProvider());
    expect(listing.unlistableNested).toEqual([join(dir, 's2', 'locked')]);
    expect(listing.unlistable).toEqual([]);
  });

  it('SKL-002 reports it as not scanned, live (engine context and its own walk)', async () => {
    const fs = new LocalFSProvider();
    for (const ctx of [await engineCtx(dir, fs), ctxOf(dir, fs)]) {
      const r = await skl002.run(ctx);
      expect(r.passed).toBe(false);
      const ev = r.evidence?.find(e => e.file === join(dir, 's2', 'locked'));
      expect(ev?.detail).toMatch(/not scanned: folder inside a skill can't be listed/);
      expect(ev?.mitigated).toBeFalsy();
      expect(r.message).toMatch(/1 skill location\(s\) not scanned/);
    }
  });

  it('the inventory says it is incomplete', async () => {
    const { inventory } = await collectSkillInventory(installation(dir), new LocalFSProvider());
    expect(inventory.incomplete).toContain(`${join(dir, 's2', 'locked')}: contents can't be listed — not scanned`);
  });

  it('a mode-111 skill directory at the root is still reported once, as before', async () => {
    await mkdir(join(dir, 'gated'));
    await writeFile(join(dir, 'gated', 'SKILL.md'), '# g\n');
    await chmod(join(dir, 'gated'), 0o111);
    try {
      const r = await skl002.run(await engineCtx(dir, new LocalFSProvider()));
      expect(r.evidence?.filter(e => e.file === join(dir, 'gated'))).toHaveLength(1);
    } finally {
      await chmod(join(dir, 'gated'), 0o755);
    }
  });
});

describe('a folder inside a skill that cannot be listed (snapshot)', () => {
  const root = '/home/u/.claude/skills';
  const snapshot = (privileged = false) => new SnapshotFSProvider({
    version: 1, hostname: 'h', platform: 'linux', homedir: '/home/u', timestamp: '2026-11-19T00:00:00Z',
    privilege: { uid: privileged ? 0 : 1000, username: 'u', isRoot: privileged, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: { [`${root}/s2/SKILL.md`]: { content: '# s2\n', mode: 0o644, exists: true } },
    directories: {}, commandOutputs: {}, env: {},
    // what the probe records for `<root>/**`: every directory's mode
    directoryModes: { [root]: 0o755, [`${root}/s2`]: 0o755, [`${root}/s2/locked`]: 0, [`${root}/s2/empty`]: 0o755 },
  });

  it('the walk lists it, as a local walk does', async () => {
    expect((await listSkillTree(root, snapshot())).unlistableNested).toEqual([`${root}/s2/locked`]);
  });

  it('SKL-002 reports it as not scanned, live', async () => {
    const r = await skl002.run(await engineCtx(root, snapshot()));
    expect(r.passed).toBe(false);
    const ev = r.evidence?.find(e => e.file === `${root}/s2/locked`);
    expect(ev?.detail).toMatch(/not scanned: folder inside a skill can't be listed/);
    expect(ev?.mitigated).toBeFalsy();
  });

  it('a probe that ran as root could list it', async () => {
    expect((await listSkillTree(root, snapshot(true))).unlistableNested).toEqual([]);
  });
});

describe('a skill file padded past the content-scan limit', () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), 'vaso-r142-'));
    await mkdir(join(dir, 'pad'));
    await writeFile(join(dir, 'pad', 'SKILL.md'), '# pad\n');
    const payload = 'eval(process.argv[2]);\n';
    await writeFile(join(dir, 'pad', 'index.js'), payload + '/*' + ' '.repeat(MAX_SCAN_FILE_BYTES) + '*/\n');
  });
  afterEach(async () => { await rm(dir, { recursive: true, force: true }); });

  it('SKL-002 reports it as not scanned — a warning, not mitigated', async () => {
    const r = await skl002.run(ctxOf(dir, new LocalFSProvider()));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('warning');
    const ev = r.evidence?.find(e => e.file === join(dir, 'pad', 'index.js'));
    expect(ev?.detail).toMatch(/not scanned: larger than the 5 MiB content-scan limit/);
    expect(ev?.mitigated).toBeFalsy();
  });

  it('the same from a snapshot whose probe left the content out for its size', async () => {
    const root = '/home/u/.claude/skills';
    const fs = new SnapshotFSProvider({
      version: 1, hostname: 'h', platform: 'linux', homedir: '/home/u', timestamp: '2026-11-19T00:00:00Z',
      privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
      files: {
        [`${root}/pad/SKILL.md`]: { content: '# pad\n', mode: 0o644, exists: true },
        [`${root}/pad/index.js`]: { mode: 0o644, exists: true, contentOmitted: true, omitted: 'size' },
      },
      directories: {}, commandOutputs: {}, env: {},
    });
    const r = await skl002.run(ctxOf(root, fs));
    expect(r.passed).toBe(false);
    const ev = r.evidence?.find(e => e.file === `${root}/pad/index.js`);
    expect(ev?.detail).toMatch(/larger than the 5 MiB/);
    expect(ev?.mitigated).toBeFalsy();
  });

  it('the content checks still skip it (SKL-002 carries the verdict)', async () => {
    expect((await skl003.run(ctxOf(dir, new LocalFSProvider()))).passed).toBe(true);
  });
});
