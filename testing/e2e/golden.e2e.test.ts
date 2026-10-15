import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, cp, mkdtemp, readdir, readFile, rm, writeFile, lstat } from 'node:fs/promises';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import type { AgentScanResult, ScanResult, Severity } from '../../src/core/types.js';

/**
 * Golden regression corpus (testing/golden/cases/<name>/): real-world and
 * vendor-documented configs with the verdicts VASO must reach on them. Each
 * case is a fixture HOME (`home/`, `{{HOME}}` substituted) and a case.json:
 *
 *   agent    the agent scanned (`-a`)
 *   source   where the config comes from (vendor doc URL, deep-test fixture)
 *   clean    true: no warning/critical finding and nothing errored — a
 *            vendor-secure config must not be flagged
 *   fail     { "<check id>": "<severity>" | "any" } — must be reported
 *   pass     [ "<check id>" ] — must pass (a fixed false positive)
 *   fix      { "resolves": [ids] } — `vaso fix -y` resolves them without
 *            breaking any other check, and `--rollback` restores every file
 *   parity   false to skip the probe-snapshot comparison (default: compared
 *            whenever Go is available to build the probe)
 *   modes    { "<path under home>": "600" } — git keeps only 644/755 file
 *            modes and none for directories, so permissions are set here
 *
 * Scans run with a minimal environment (no real HOME, PATH without agent
 * CLIs) from inside the fixture, so results depend on the fixture only.
 */

const ROOT = resolve(import.meta.dirname, '../..');
const CLI = join(ROOT, 'dist/cli.js');
const CASES = join(ROOT, 'testing/golden/cases');

interface GoldenCase {
  agent: string;
  source: string;
  clean?: boolean;
  fail?: Record<string, Severity | 'any'>;
  pass?: string[];
  fix?: { resolves: string[] };
  parity?: boolean;
  modes?: Record<string, string>;
  /** Skip on these platforms (fixtures relying on POSIX modes). */
  skipOn?: NodeJS.Platform[];
}

const caseNames = existsSync(CASES)
  ? readdirSync(CASES).filter(n => existsSync(join(CASES, n, 'case.json'))).sort()
  : [];

function run(args: string[], home: string, cmd = process.execPath): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((done, fail) => {
    const child = spawn(cmd, cmd === process.execPath ? [CLI, ...args] : args, {
      cwd: home,
      env: { HOME: home, PATH: '/usr/bin:/bin', NO_COLOR: '1', VASO_SKIP_IOC_UPDATE: '1', TMPDIR: tmpdir() },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
    child.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
    child.on('error', fail);
    child.on('close', code => done({ code: code ?? 1, stdout, stderr }));
  });
}

async function scan(home: string, agent: string, extra: string[] = []): Promise<ScanResult> {
  const out = join(home, '..', `scan-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  const r = await run(['scan', '-a', agent, '-f', 'json', '-o', out, ...extra], home);
  if (r.code > 1) throw new Error(`scan exited ${r.code}: ${r.stderr}`);
  return JSON.parse(await readFile(out, 'utf-8')) as ScanResult;
}

/** Copy the fixture, substituting {{HOME}} in text files; modes are kept. */
async function materialize(src: string, dest: string): Promise<void> {
  await cp(src, dest, { recursive: true, preserveTimestamps: true, verbatimSymlinks: true });
  for (const entry of await readdir(dest, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const p = join(entry.parentPath, entry.name);
    const text = await readFile(p, 'utf-8').catch(() => undefined);
    if (text?.includes('{{HOME}}')) await writeFile(p, text.split('{{HOME}}').join(dest));
  }
}

/** Content + mode hash of every file under `dir` (rollback must restore both). */
async function treeHash(dir: string, skip: string): Promise<Record<string, string>> {
  const out: Record<string, string> = {};
  for (const entry of await readdir(dir, { recursive: true, withFileTypes: true })) {
    const p = join(entry.parentPath, entry.name);
    if (p.startsWith(skip)) continue;
    const st = await lstat(p);
    out[p] = entry.isFile()
      ? `${(st.mode & 0o7777).toString(8)}:${createHash('sha256').update(await readFile(p)).digest('hex')}`
      : `${(st.mode & 0o7777).toString(8)}:${entry.isDirectory() ? 'dir' : 'other'}`;
  }
  return out;
}

const SEVERE = new Set<Severity>(['warning', 'critical']);
const verdicts = (a: AgentScanResult) =>
  Object.fromEntries(a.results.map(r => [r.id, `${r.passed ? 'pass' : 'fail'}/${r.severity}${r.errored ? '/errored' : ''}`]));

let probe: string | undefined;
const goAvailable = (() => {
  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

beforeAll(async () => {
  if (!goAvailable || caseNames.length === 0) return;
  const dir = await mkdtemp(join(tmpdir(), 'vaso-golden-probe-'));
  probe = join(dir, 'vaso-probe');
  execFileSync('go', ['build', '-o', probe, '.'], { cwd: join(ROOT, 'probe'), stdio: 'ignore' });
}, 300_000);

describe.each(caseNames)('golden: %s', (name) => {
  const spec = JSON.parse(readFileSync(join(CASES, name, 'case.json'), 'utf-8')) as GoldenCase;
  const skip = spec.skipOn?.includes(process.platform) ?? false;
  let work: string;
  let home: string;
  let local: AgentScanResult[];

  beforeAll(async () => {
    if (skip) return;
    work = await mkdtemp(join(tmpdir(), `vaso-golden-${name}-`));
    home = join(work, 'home');
    await materialize(join(CASES, name, 'home'), home);
    for (const [path, mode] of Object.entries(spec.modes ?? {})) await chmod(join(home, path), parseInt(mode, 8));
    local = (await scan(home, spec.agent)).agents.filter(a => a.agent === spec.agent);
  }, 120_000);

  afterAll(async () => {
    if (work) await rm(work, { recursive: true, force: true });
  });

  it.skipIf(skip)('reaches the expected verdicts', () => {
    expect(local.length, 'agent detected').toBeGreaterThan(0);
    const results = local.flatMap(a => a.results);
    for (const [id, severity] of Object.entries(spec.fail ?? {})) {
      const hit = results.find(r => r.id === id && !r.passed);
      expect(hit, `${id} should be reported`).toBeDefined();
      if (severity !== 'any') expect(hit!.severity, `${id} severity`).toBe(severity);
    }
    for (const id of spec.pass ?? []) {
      expect(results.filter(r => r.id === id && !r.passed).map(r => r.message), `${id} should pass`).toEqual([]);
    }
    if (spec.clean) {
      const flagged = results.filter(r => r.errored || (!r.passed && SEVERE.has(r.severity)));
      expect(flagged.map(r => `${r.id} ${r.severity}: ${r.message}`), 'vendor-secure config flagged').toEqual([]);
    }
  });

  it.skipIf(skip || spec.parity === false || !goAvailable)('remote (probe snapshot) reaches the same verdicts', async () => {
    const manifest = join(work, 'manifest.json');
    const snapshot = join(work, 'snapshot.json');
    await writeFile(manifest, (await run(['probe', 'manifest'], home)).stdout);
    const p = await run(['--manifest', manifest], home, probe!);
    expect(p.code).toBe(0);
    await writeFile(snapshot, p.stdout);
    const remote = (await scan(home, spec.agent, ['--snapshot', snapshot])).agents.filter(a => a.agent === spec.agent);
    const key = (as: AgentScanResult[]) => Object.fromEntries(as.map(a => [a.installation.installDir, verdicts(a)]));
    expect(key(remote)).toEqual(key(local));
  }, 120_000);

  it.skipIf(skip || !spec.fix)('fix resolves the findings without breaking others, and rollback restores every file', async () => {
    const before = await treeHash(home, join(home, '.vaso'));
    const fixed = await run(['fix', '-a', spec.agent, '-y'], home);
    expect(fixed.code, fixed.stdout + fixed.stderr).toBe(0);

    const after = (await scan(home, spec.agent)).agents.filter(a => a.agent === spec.agent);
    const afterResults = after.flatMap(a => a.results);
    for (const id of spec.fix!.resolves) {
      expect(afterResults.filter(r => r.id === id && !r.passed).map(r => r.message), `${id} after fix`).toEqual([]);
    }
    // A fix must not make another check fail (or error) that passed before
    const passedBefore = new Set(local.flatMap(a => a.results).filter(r => r.passed).map(r => r.id));
    const broken = afterResults.filter(r => passedBefore.has(r.id) && (!r.passed || r.errored));
    expect(broken.map(r => `${r.id}: ${r.message}`), 'checks broken by the fix').toEqual([]);

    const rolled = await run(['fix', '--rollback'], home);
    expect(rolled.code, rolled.stdout + rolled.stderr).toBe(0);
    expect(await treeHash(home, join(home, '.vaso'))).toEqual(before);
  }, 180_000);
});

if (caseNames.length === 0) {
  it('golden corpus present', () => {
    expect(caseNames.length).toBeGreaterThan(0);
  });
}
