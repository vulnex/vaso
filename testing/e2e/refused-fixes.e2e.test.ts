import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, execFileSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import type { AgentScanResult, ScanResult } from '../../src/core/types.js';

/**
 * Findings whose fix `vaso fix` would always refuse — an install outside the
 * home, a config that is a symlink — are not offered to it: the scan says
 * why, `vaso fix -y` changes nothing there and exits 0, twice, and a probe
 * snapshot reaches the same verdicts.
 */

const ROOT = resolve(import.meta.dirname, '../..');
const CLI = join(ROOT, 'dist/cli.js');

const goAvailable = (() => {
  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
})();

function run(args: string[], home: string, extraEnv: Record<string, string> = {}, cmd = process.execPath): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((done, fail) => {
    const child = spawn(cmd, cmd === process.execPath ? [CLI, ...args] : args, {
      cwd: home,
      env: { HOME: home, PATH: '/usr/bin:/bin', NO_COLOR: '1', VASO_SKIP_IOC_UPDATE: '1', TMPDIR: tmpdir(), ...extraEnv },
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

let work: string;
let probe: string | undefined;

beforeAll(async () => {
  work = await mkdtemp(join(realpathSync(tmpdir()), 'vaso-refused-'));
  await chmod(work, 0o755);
  if (goAvailable) {
    probe = join(work, 'vaso-probe');
    execFileSync('go', ['build', '-o', probe, '.'], { cwd: join(ROOT, 'probe'), stdio: 'ignore' });
  }
}, 300_000);

afterAll(async () => {
  if (work) await rm(work, { recursive: true, force: true });
});

const put = async (path: string, mode: number, content: string) => {
  await mkdir(dirname(path), { recursive: true, mode: 0o755 });
  await writeFile(path, content);
  await chmod(path, mode);
};

interface Layout {
  name: string;
  agent: string;
  build(base: string, home: string): Promise<{ env: Record<string, string>; watched: string[] }>;
  /** Check id → the note its message must carry */
  notes: Record<string, RegExp>;
}

const layouts: Layout[] = [
  {
    name: 'CODEX_HOME outside the home with a world-readable auth.json',
    agent: 'codex',
    async build(base) {
      const codex = join(base, 'data', 'codex');
      await put(join(codex, 'auth.json'), 0o644, '{"OPENAI_API_KEY":"sk-test"}\n');
      await put(join(codex, 'config.toml'), 0o644, 'approval_policy = "on-request"\n');
      return { env: { CODEX_HOME: codex }, watched: [join(codex, 'auth.json')] };
    },
    notes: { 'CDX-003': /not changed by vaso fix: .*\/data\/codex\/auth\.json is outside the home/ },
  },
  {
    name: 'an OpenClaw config that is a symlink',
    agent: 'openclaw',
    async build(_base, home) {
      const real = join(home, 'dotfiles', 'openclaw.json');
      await put(real, 0o600, '{"gateway":{"bind":"lan","auth":{"mode":"token","token":"x"}}}\n');
      await mkdir(join(home, '.openclaw'), { recursive: true, mode: 0o700 });
      await symlink(real, join(home, '.openclaw', 'openclaw.json'));
      return { env: {}, watched: [real] };
    },
    notes: { 'CFG-001': /not changed by vaso fix: .*\/\.openclaw\/openclaw\.json is a symlink/ },
  },
];

describe.each(layouts)('$name', (layout) => {
  let home: string;
  let env: Record<string, string>;
  let watched: string[];
  let local: AgentScanResult[];

  async function scan(extra: string[] = []): Promise<AgentScanResult[]> {
    const out = join(home, '..', `scan-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
    const r = await run(['scan', '-a', layout.agent, '-f', 'json', '-o', out, ...extra], home, env);
    if (r.code > 1) throw new Error(`scan exited ${r.code}: ${r.stderr}`);
    return (JSON.parse(await readFile(out, 'utf-8')) as ScanResult).agents.filter(a => a.agent === layout.agent);
  }
  const verdicts = (as: AgentScanResult[]) => Object.fromEntries(as.flatMap(a => a.results.map(r =>
    [`${a.installation.installDir} ${r.id}`, `${r.passed ? 'pass' : 'fail'}/${r.severity}/${r.fixable ? 'fixable' : '-'}`])));

  beforeAll(async () => {
    const base = await mkdtemp(join(work, 'case-'));
    await chmod(base, 0o755);
    home = join(base, 'home');
    await mkdir(home, { recursive: true, mode: 0o755 });
    ({ env, watched } = await layout.build(base, home));
    local = await scan();
  }, 120_000);

  it('the finding says why vaso fix leaves it, and nothing refusable is offered', () => {
    const results = local.flatMap(a => a.results);
    for (const [id, note] of Object.entries(layout.notes)) {
      const r = results.find(x => x.id === id && !x.passed);
      expect(r, id).toBeDefined();
      expect(r!.fixable).toBe(false);
      // Under a private temporary directory (macOS) the file's parents already
      // block other users: informational, never fixable — nothing to note
      if (r!.evidence?.every(e => e.mitigated)) continue;
      expect(r!.message).toMatch(note);
    }
  });

  it('vaso fix changes nothing there and exits 0, twice', async () => {
    const before = await Promise.all(watched.map(async p => [(await stat(p)).mode, await readFile(p, 'utf-8')]));
    for (let i = 0; i < 2; i++) {
      const f = await run(['fix', '-a', layout.agent, '-y'], home, env);
      expect(f.code, f.stdout + f.stderr).toBe(0);
    }
    expect(await Promise.all(watched.map(async p => [(await stat(p)).mode, await readFile(p, 'utf-8')]))).toEqual(before);
  });

  it.skipIf(!goAvailable)('a probe snapshot reaches the same verdicts and notes', async () => {
    const manifest = join(home, '..', 'manifest.json');
    const snapshot = join(home, '..', 'snapshot.json');
    await writeFile(manifest, (await run(['probe', 'manifest'], home, env)).stdout);
    const p = await run(['--manifest', manifest], home, env, probe!);
    expect(p.code).toBe(0);
    await writeFile(snapshot, p.stdout);
    const remote = await scan(['--snapshot', snapshot]);
    expect(verdicts(remote)).toEqual(verdicts(local));
    for (const id of Object.keys(layout.notes)) {
      const message = (as: AgentScanResult[]) => as.flatMap(a => a.results).find(x => x.id === id && !x.passed)?.message;
      expect(message(remote)).toEqual(message(local));
    }
  }, 120_000);
});
