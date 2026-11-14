import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, rm, chmod, stat, symlink, readdir, lstat, link, rename } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

// rollback() and the engine find ~/.vaso through os.homedir()
const home = { dir: '' };
vi.mock('node:os', async (orig) => ({ ...(await orig<typeof import('node:os')>()), homedir: () => home.dir }));

import { rollback } from './rollback.js';
import { RemediationEngine } from './engine.js';
import { CheckRegistry } from '../core/check-registry.js';
import { defineCheck } from '../core/check-builder.js';
import type { ScanResult, CheckResult } from '../core/types.js';
import { chmodNoFollow, writeRegularFile } from './safe-file.js';
import { restrictFilesToOwner } from './config-writer.js';

const posix = process.platform !== 'win32';
let logs: string[] = [];

/** A fix run through the real engine: `edit` changes the file the way a fix would. */
async function runFix(file: string, edit: (path: string) => Promise<void>, evidence: string[] = [file], installDir?: string): Promise<string[]> {
  const registry = new CheckRegistry();
  registry.register(defineCheck({
    id: 'TST-001', name: 't', category: 'config', severity: 'warning', description: 't',
    async run(_ctx, h) { return h.passed('x'); },
    async fix() {
      await edit(file);
      return { checkId: 'TST-001', applied: true, message: 'edited' };
    },
  }));
  const finding: CheckResult = {
    id: 'TST-001', name: 't', category: 'config', severity: 'warning', passed: false, message: 'bad',
    fixable: true, evidence: evidence.map(f => ({ file: f })),
  };
  const result: ScanResult = {
    timestamp: 't', totalScore: 0, totalGrade: 'F', fleetAverage: 0,
    summary: { critical: 0, warning: 1, info: 0, passed: 0, total: 1 },
    agents: [{ agent: 'openclaw', installation: { agent: 'openclaw', installDir: installDir ?? home.dir, configFiles: [] }, results: [finding], score: 0, grade: 'F' }],
  };
  await new RemediationEngine(registry).fix(result, { yes: true });
  return readdir(join(home.dir, '.vaso', 'backups')).catch(() => []);
}

describe('fix + rollback (real files)', () => {
  beforeEach(async () => {
    home.dir = await mkdtemp(join(tmpdir(), 'vaso-rb-'));
    logs = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { logs.push(a.map(String).join(' ')); });
    process.exitCode = undefined;
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
    await rm(home.dir, { recursive: true, force: true });
  });

  it('reports a missing backups dir', async () => {
    await rollback();
    expect(logs.some(l => l.includes('No backups found'))).toBe(true);
  });

  it('restores content and the exact mode', async () => {
    const f = join(home.dir, 'config.json');
    await writeFile(f, '{"a":1}\n');
    if (posix) await chmod(f, 0o640);
    await runFix(f, async p => { await writeRegularFile(p, '{"a":2}\n'); if (posix) await chmodNoFollow(p, 0o600); });
    expect(await readFile(f, 'utf-8')).toBe('{"a":2}\n');
    await rollback();
    expect(await readFile(f, 'utf-8')).toBe('{"a":1}\n');
    if (posix) expect((await stat(f)).mode & 0o7777).toBe(0o640);
    expect(process.exitCode).toBeUndefined();
  });

  it('a dry run lists what it would restore and changes nothing', async () => {
    const f = join(home.dir, 'config.json');
    await writeFile(f, '{"a":1}\n');
    const [backup] = await runFix(f, p => writeRegularFile(p, '{"a":2}\n'));
    logs = [];
    await rollback(undefined, { dryRun: true });
    expect(await readFile(f, 'utf-8')).toBe('{"a":2}\n');
    expect(await readdir(join(home.dir, '.vaso', 'backups'))).toEqual([backup]);
    expect(logs.join('\n')).toMatch(/Would restore .*config\.json/);
    // the backup is still pending: a real rollback restores it
    await rollback();
    expect(await readFile(f, 'utf-8')).toBe('{"a":1}\n');
  });

  it.skipIf(!posix)('restores a read-only file', async () => {
    const f = join(home.dir, 'auth.json');
    await writeFile(f, 'secret');
    await chmod(f, 0o444);
    await runFix(f, p => chmodNoFollow(p, 0o400));
    expect((await stat(f)).mode & 0o777).toBe(0o400);
    await rollback();
    expect((await stat(f)).mode & 0o777).toBe(0o444);
    expect(await readFile(f, 'utf-8')).toBe('secret');
  });

  it.skipIf(!posix)('restores the mode of a directory a fix chmod-ed', async () => {
    const d = join(home.dir, 'allowlist');
    await mkdir(d);
    await chmod(d, 0o777);
    await runFix(d, p => chmodNoFollow(p, 0o700));
    expect((await stat(d)).mode & 0o777).toBe(0o700);
    await rollback();
    expect((await stat(d)).mode & 0o777).toBe(0o777);
  });

  it.skipIf(!posix)('restores a directory the fix chmod-ed without the finding naming it', async () => {
    const f = join(home.dir, 'allowlist.json');
    const d = join(home.dir, 'conf');
    await writeFile(f, '{}');
    await mkdir(d);
    await chmod(d, 0o755);
    await runFix(f, async () => { await chmodNoFollow(d, 0o700); });
    expect((await stat(d)).mode & 0o777).toBe(0o700);
    await rollback();
    expect((await stat(d)).mode & 0o777).toBe(0o755);
    expect(process.exitCode).toBeUndefined();
  });

  it.skipIf(!posix || process.getuid?.() === 0)('restores the mode of a file the owner could not read', async () => {
    const f = join(home.dir, 'token.json');
    await writeFile(f, 'secret');
    await chmod(f, 0o044);
    await runFix(f, p => chmodNoFollow(p, 0o000));
    expect((await stat(f)).mode & 0o777).toBe(0);
    await rollback();
    expect((await stat(f)).mode & 0o777).toBe(0o044);
    await chmod(f, 0o600);
    expect(await readFile(f, 'utf-8')).toBe('secret');
  });

  it('keeps an edit made after the fix instead of discarding it', async () => {
    const f = join(home.dir, 'config.toml');
    await writeFile(f, 'a = 1\n');
    await runFix(f, p => writeRegularFile(p, 'a = 2\n'));
    await writeFile(f, 'a = 2\nmine = true\n'); // the user's later edit
    await rollback();
    expect(await readFile(f, 'utf-8')).toBe('a = 2\nmine = true\n');
    expect(logs.some(l => l.includes('changed after the fix'))).toBe(true);
    expect(process.exitCode).toBe(2);
  });

  it('does not block on a file the fix never changed, edited since', async () => {
    const fixed = join(home.dir, 'openclaw.json');
    const untouched = join(home.dir, '.env');
    await writeFile(fixed, '{"a":1}\n');
    await writeFile(untouched, 'A=1\n');
    // the fix edits one file; the other is only backed up (it is in the evidence)
    await runFix(fixed, p => writeRegularFile(p, '{"a":2}\n'), [fixed, untouched]);
    await writeFile(untouched, 'A=1\nB=2\n'); // the user's later edit
    await rollback();
    expect(await readFile(fixed, 'utf-8')).toBe('{"a":1}\n');
    expect(await readFile(untouched, 'utf-8')).toBe('A=1\nB=2\n');
    expect(process.exitCode).toBeUndefined();
  });

  it.skipIf(!posix)('never writes through a symlink that replaced the original', async () => {
    const f = join(home.dir, 'settings.json');
    const canary = join(home.dir, 'canary.txt');
    await writeFile(f, 'orig');
    await writeFile(canary, 'canary');
    await chmod(canary, 0o600);
    await runFix(f, p => writeRegularFile(p, 'fixed'));
    await rm(f);
    await symlink(canary, f);
    await rollback();
    expect(await readFile(canary, 'utf-8')).toBe('canary');
    expect((await stat(canary)).mode & 0o777).toBe(0o600);
    expect(logs.some(l => l.includes('now a symlink'))).toBe(true);
    expect(process.exitCode).toBe(2);
  });

  it.skipIf(!posix)('refuses to fix (and back up) a symlinked config or a FIFO', async () => {
    const target = join(home.dir, 'elsewhere.json');
    const link = join(home.dir, 'config.json');
    await writeFile(target, '{}');
    await symlink(target, link);
    await runFix(link, p => writeRegularFile(p, '{"fixed":true}'));
    expect(await readFile(target, 'utf-8')).toBe('{}');
    expect(logs.some(l => l.includes('is a symlink'))).toBe(true);

    const fifo = join(home.dir, 'launcher-config.json');
    execFileSync('mkfifo', [fifo]);
    await runFix(fifo, p => writeRegularFile(p, 'x')); // must return, not hang
    expect((await lstat(fifo)).isFIFO()).toBe(true);
  });

  it.skipIf(!posix)('refuses an install dir relocated outside $HOME — rollback could not restore it (dt17)', async () => {
    const outside = await mkdtemp(join(tmpdir(), 'vaso-rb-relocated-'));
    try {
      const cfg = join(outside, 'settings.json');
      await writeFile(cfg, '{"v":1}');
      await chmod(cfg, 0o644);
      await runFix(cfg, async p => { await writeRegularFile(p, '{"v":2}'); }, [cfg], outside);
      await runFix(cfg, p => chmodNoFollow(p, 0o600), [cfg], outside);
      expect(await readFile(cfg, 'utf-8')).toBe('{"v":1}');
      expect((await stat(cfg)).mode & 0o777).toBe(0o644);
      expect(logs.some(l => l.includes('where rollback can restore it'))).toBe(true);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  it.skipIf(!posix)('refuses a hard-linked file: the change would reach the other name', async () => {
    const outside = await mkdtemp(join(tmpdir(), 'vaso-rb-victim-'));
    try {
      const victim = join(outside, 'victim.json');
      await writeFile(victim, '{"v":1}');
      await chmod(victim, 0o644);
      const cfg = join(home.dir, 'config.json');
      await link(victim, cfg);
      await runFix(cfg, async p => { await writeRegularFile(p, '{"v":2}'); });
      await runFix(cfg, p => chmodNoFollow(p, 0o600));
      expect(await readFile(victim, 'utf-8')).toBe('{"v":1}');
      expect((await stat(victim)).mode & 0o777).toBe(0o644);
      expect(logs.some(l => l.includes('hard links'))).toBe(true);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  it.skipIf(!posix)('rolls back a run that refused a hard-linked file next to one it fixed', async () => {
    const outside = await mkdtemp(join(tmpdir(), 'vaso-rb-victim-'));
    try {
      const victim = join(outside, 'auth.json');
      await writeFile(victim, 'secret');
      await chmod(victim, 0o644);
      const linked = join(home.dir, 'auth.json');
      await link(victim, linked);
      const plain = join(home.dir, 'config.json');
      await writeFile(plain, '{"a":1}');
      await chmod(plain, 0o644);
      // one run: the plain file is fixed, the hard-linked one refused
      await runFix(plain, async p => {
        await chmodNoFollow(p, 0o600);
        await chmodNoFollow(linked, 0o600).catch(() => undefined);
      }, [plain, linked]);
      expect((await stat(plain)).mode & 0o777).toBe(0o600);
      await rollback();
      expect((await stat(plain)).mode & 0o777).toBe(0o644);
      expect((await stat(victim)).mode & 0o777).toBe(0o644);
      expect(process.exitCode).toBeUndefined(); // not stuck pending
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  it.skipIf(!posix)('refuses a config reached through a symlinked directory that leaves the home, allows one inside it', async () => {
    const outside = await mkdtemp(join(tmpdir(), 'vaso-rb-etc-'));
    try {
      await writeFile(join(outside, 'passwd'), 'root:x:0:0\n');
      await chmod(join(outside, 'passwd'), 0o644);
      await symlink(outside, join(home.dir, '.picoclaw'));
      await runFix(join(home.dir, '.picoclaw', 'passwd'), p => chmodNoFollow(p, 0o600));
      expect((await stat(join(outside, 'passwd'))).mode & 0o777).toBe(0o644);
      expect(logs.some(l => l.includes('outside'))).toBe(true);

      // a dotfiles repo inside the home is fine
      await mkdir(join(home.dir, 'dotfiles', 'nb'), { recursive: true });
      await writeFile(join(home.dir, 'dotfiles', 'nb', 'config.json'), '{}');
      await chmod(join(home.dir, 'dotfiles', 'nb', 'config.json'), 0o644);
      await symlink(join(home.dir, 'dotfiles', 'nb'), join(home.dir, '.nanobot'));
      await runFix(join(home.dir, '.nanobot', 'config.json'), p => chmodNoFollow(p, 0o600));
      expect((await stat(join(home.dir, 'dotfiles', 'nb', 'config.json'))).mode & 0o777).toBe(0o600);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });

  it.skipIf(!posix)('a permission fix still fixes the other files when one is a symlink, and names it', async () => {
    const real = join(home.dir, 'real.json');
    const target = join(home.dir, 'elsewhere.json');
    const linked = join(home.dir, 'linked.json');
    await writeFile(real, '{}');
    await writeFile(target, '{}');
    await chmod(real, 0o644);
    await chmod(target, 0o644);
    await symlink(target, linked);
    const result = await restrictFilesToOwner('CFG-003', [real, linked]);
    expect((await stat(real)).mode & 0o777).toBe(0o600);
    expect((await stat(target)).mode & 0o777).toBe(0o644);
    expect(result.applied).toBe(true);
    expect(result.message).toMatch(/linked\.json is a symlink/);
  });

  it.skipIf(!posix)('rollback refuses a path whose directory was re-pointed after the fix', async () => {
    const dir = join(home.dir, '.agent');
    await mkdir(dir);
    const f = join(dir, 'config.json');
    await writeFile(f, 'orig');
    await runFix(f, p => writeRegularFile(p, 'fixed'));
    const decoy = await mkdtemp(join(tmpdir(), 'vaso-rb-decoy-'));
    try {
      await writeFile(join(decoy, 'config.json'), 'decoy');
      await rename(dir, join(home.dir, '.agent-moved'));
      await symlink(decoy, dir);
      await rollback();
      expect(await readFile(join(decoy, 'config.json'), 'utf-8')).toBe('decoy');
      expect(logs.some(l => l.includes('resolves somewhere else'))).toBe(true);
      expect(process.exitCode).toBe(2);
    } finally {
      await rm(decoy, { recursive: true, force: true });
    }
  });

  it.skipIf(!posix)('backs up thousands of files a fix chmods in linear time, and rolls them all back', async () => {
    const dir = join(home.dir, 'mcp-tokens');
    await mkdir(dir);
    const files: string[] = [];
    for (let i = 0; i < 6000; i++) {
      const f = join(dir, `t${i}.json`);
      await writeFile(f, `{"i":${i}}`);
      await chmod(f, 0o644);
      files.push(f);
    }
    const start = Date.now();
    await runFix(files[0], async () => { await restrictFilesToOwner('HM-003', files); }, [files[0]]);
    // was quadratic: the whole manifest rewritten per file (5000 files ≈ 9 s, 20000 ≈ 121 s)
    expect(Date.now() - start).toBeLessThan(15_000);
    expect((await stat(files[5999])).mode & 0o777).toBe(0o600);
    await rollback();
    expect((await stat(files[5999])).mode & 0o777).toBe(0o644);
    expect((await stat(files[0])).mode & 0o777).toBe(0o644);
  }, 120_000);

  it('restores backups made before the manifest existed', async () => {
    const f = join(home.dir, 'legacy.env');
    await writeFile(f, 'A=fixed\n');
    const backup = join(home.dir, '.vaso', 'backups', '2026-01-01T00-00-00-000Z');
    await mkdir(join(backup, home.dir), { recursive: true });
    await writeFile(join(backup, f), 'A=orig\n');
    await rollback();
    expect(await readFile(f, 'utf-8')).toBe('A=orig\n');
  });

  it('matches a named backup and reports an unknown one', async () => {
    await mkdir(join(home.dir, '.vaso', 'backups', '2026-02-15T12-30-00'), { recursive: true });
    await rollback('2099-12-31');
    expect(logs.some(l => l.includes('No backup matching'))).toBe(true);
    expect(process.exitCode).toBe(2);
    process.exitCode = undefined;
    await rollback('2026-02-15');
    expect(logs.some(l => l.includes('2026-02-15T12-30-00'))).toBe(true);
  });

  it('a fix run that applies nothing leaves no backup; rollback still undoes the run before it', async () => {
    const f = join(home.dir, 'settings.json');
    await writeFile(f, '{"p":"always"}\n');
    const first = await runFix(f, p => writeRegularFile(p, '{"p":"ask"}\n'));
    expect(first).toHaveLength(1);

    // second run: the fix finds nothing to change
    const registry = new CheckRegistry();
    registry.register(defineCheck({
      id: 'TST-002', name: 't', category: 'config', severity: 'warning', description: 't',
      async run(_ctx, h) { return h.passed('x'); },
      async fix() { return { checkId: 'TST-002', applied: false, alreadyDone: true, message: 'already "ask"' }; },
    }));
    const finding: CheckResult = { id: 'TST-002', name: 't', category: 'config', severity: 'warning', passed: false, message: 'bad', fixable: true, evidence: [{ file: f }] };
    await new RemediationEngine(registry).fix({
      timestamp: 't', totalScore: 0, totalGrade: 'F', fleetAverage: 0,
      summary: { critical: 0, warning: 1, info: 0, passed: 0, total: 1 },
      agents: [{ agent: 'openclaw', installation: { agent: 'openclaw', installDir: home.dir, configFiles: [] }, results: [finding], score: 0, grade: 'F' }],
    }, { yes: true });
    expect(await readdir(join(home.dir, '.vaso', 'backups'))).toEqual(first);

    await rollback();
    expect(await readFile(f, 'utf-8')).toBe('{"p":"always"}\n');
  });

  it('rollback skips an empty backup an older version left after a no-op run', async () => {
    const f = join(home.dir, 'settings.json');
    await writeFile(f, '{"p":"always"}\n');
    if (posix) await chmod(f, 0o600);
    const [real] = await runFix(f, p => writeRegularFile(p, '{"p":"ask"}\n'));
    // what 1.3.1 wrote for a run that changed nothing: a copy and after = before
    const { sha256 } = await import('./backup-manifest.js');
    const empty = join(home.dir, '.vaso', 'backups', '2099-01-01T00-00-00-000Z');
    await mkdir(join(empty, home.dir), { recursive: true });
    const now = await readFile(f);
    await writeFile(join(empty, f), now);
    const mode = (await stat(f)).mode & 0o7777;
    await writeFile(join(empty, '.vaso-manifest.json'), `${JSON.stringify({ path: f, kind: 'file', mode, before: sha256(now) })}\n${JSON.stringify({ path: f, after: sha256(now) })}\n`);

    await rollback();
    expect(logs.some(l => l.includes('Skipping backup 2099-01-01T00-00-00-000Z'))).toBe(true);
    expect(logs.some(l => l.includes(`Restoring from backup: ${real}`))).toBe(true);
    expect(await readFile(f, 'utf-8')).toBe('{"p":"always"}\n');
  });
});

describe('rollback confinement (dt14)', () => {
  beforeEach(async () => {
    home.dir = await mkdtemp(join(tmpdir(), 'vaso-rb-'));
    vi.spyOn(console, 'log').mockImplementation(() => {});
    process.exitCode = undefined;
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
    await rm(home.dir, { recursive: true, force: true });
  });

  it.skipIf(!posix)('a tampered backup tree cannot make rollback write outside the home or through a symlinked dir', async () => {
    const outside = await mkdtemp(join(tmpdir(), 'vaso-rb-out-'));
    try {
      const target = join(outside, 'target.txt');
      await writeFile(target, 'original');
      await mkdir(join(outside, 'real'));
      await symlink(join(outside, 'real'), join(home.dir, 'link'));
      const stamp = join(home.dir, '.vaso', 'backups', '2026-10-16T00-00-00-000Z');
      // no manifest (legacy shape): an outside path, and a new file via a symlinked dir
      await mkdir(join(stamp, outside), { recursive: true });
      await writeFile(join(stamp, target), 'PWNED');
      await mkdir(join(stamp, home.dir, 'link'), { recursive: true });
      await writeFile(join(stamp, home.dir, 'link', 'new.txt'), 'PWNED');
      await rollback();
      expect(await readFile(target, 'utf-8')).toBe('original');
      expect(await readdir(join(outside, 'real'))).toEqual([]);
      expect(process.exitCode).toBe(2);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });
});

describe('rollback restores only what the fix run changed', () => {
  beforeEach(async () => {
    home.dir = await mkdtemp(join(tmpdir(), 'vaso-rb-'));
    logs = [];
    vi.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { logs.push(a.map(String).join(' ')); });
    process.exitCode = undefined;
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    process.exitCode = undefined;
    await rm(home.dir, { recursive: true, force: true });
  });

  it.skipIf(!posix)('keeps a chmod made since the fix on a file the fix never touched', async () => {
    const touched = join(home.dir, 'config.json');
    const bystander = join(home.dir, 'auth.json');
    await writeFile(touched, '{"a":1}\n');
    await writeFile(bystander, '{}\n');
    await chmod(bystander, 0o644);
    // the bystander is named in the evidence, so it is backed up as a precaution
    await runFix(touched, p => writeRegularFile(p, '{"a":2}\n'), [touched, bystander]);
    await chmod(bystander, 0o600);
    await rollback();
    expect(await readFile(touched, 'utf-8')).toBe('{"a":1}\n');
    expect((await stat(bystander)).mode & 0o7777).toBe(0o600);
    expect(process.exitCode).toBeUndefined();
    expect(logs.some(l => l.includes('Rollback complete: 1 item(s) restored (1 unchanged'))).toBe(true);
  });

  it.skipIf(!posix)('keeps the mode of a file whose content alone the fix changed', async () => {
    const f = join(home.dir, 'config.json');
    await writeFile(f, '{"a":1}\n');
    await chmod(f, 0o644);
    await runFix(f, p => writeRegularFile(p, '{"a":2}\n'));
    await chmod(f, 0o600);
    await rollback();
    expect(await readFile(f, 'utf-8')).toBe('{"a":1}\n');
    expect((await stat(f)).mode & 0o7777).toBe(0o600);
  });

  it.skipIf(!posix)('skips a mode the user changed again after a permission fix', async () => {
    const f = join(home.dir, 'cred.json');
    await writeFile(f, '{}\n');
    await chmod(f, 0o644);
    await runFix(f, async p => { await restrictFilesToOwner('TST-001', [p]); });
    expect((await stat(f)).mode & 0o7777).toBe(0o600);
    await chmod(f, 0o400);
    await rollback();
    expect((await stat(f)).mode & 0o7777).toBe(0o400);
    expect(process.exitCode).toBe(2);
    expect(logs.some(l => l.includes('its mode was changed after the fix'))).toBe(true);
    expect(logs.some(l => l.includes('Rollback incomplete'))).toBe(true);
  });

  it('exits 2 for a named backup when no backups exist', async () => {
    await rollback('nonexist');
    expect(process.exitCode).toBe(2);
  });
});
