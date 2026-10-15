import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, rm, chmod, stat, symlink, readdir, lstat } from 'node:fs/promises';
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

const posix = process.platform !== 'win32';
let logs: string[] = [];

/** A fix run through the real engine: `edit` changes the file the way a fix would. */
async function runFix(file: string, edit: (path: string) => Promise<void>, evidence: string[] = [file]): Promise<string[]> {
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
    agents: [{ agent: 'openclaw', installation: { agent: 'openclaw', installDir: home.dir, configFiles: [] }, results: [finding], score: 0, grade: 'F' }],
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
    let edited = false;
    await runFix(link, async () => { edited = true; });
    expect(edited).toBe(false);
    expect(logs.some(l => l.includes('is a symlink'))).toBe(true);

    const fifo = join(home.dir, 'launcher-config.json');
    execFileSync('mkfifo', [fifo]);
    edited = false;
    await runFix(fifo, async () => { edited = true; }); // must return, not hang
    expect(edited).toBe(false);
    expect((await lstat(fifo)).isFIFO()).toBe(true);
  });

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
});
