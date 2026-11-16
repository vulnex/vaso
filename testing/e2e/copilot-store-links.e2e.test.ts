import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, execFileSync } from 'node:child_process';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { realpathSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import type { AgentScanResult, CheckResult, ScanResult } from '../../src/core/types.js';

/**
 * Copilot's private stores reached through a link that isn't the agent's —
 * a store folder linked to a file (~/.ssh/id_rsa), ~/.copilot itself linked
 * out of the home or into a credential store — and a folder set outside the
 * home with COPILOT_HOME: a local scan and a probe snapshot reach the same
 * verdicts, no name from behind such a link ships, and nothing is offered to
 * `vaso fix` that it would refuse.
 */

const ROOT = resolve(import.meta.dirname, '../..');
const CLI = join(ROOT, 'dist/cli.js');
const CANARY = 'CANARYSTORELINK';

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
  work = await mkdtemp(join(realpathSync(tmpdir()), 'vaso-cop-links-'));
  await chmod(work, 0o755);
  if (goAvailable) {
    probe = join(work, 'vaso-probe');
    execFileSync('go', ['build', '-o', probe, '.'], { cwd: join(ROOT, 'probe'), stdio: 'ignore' });
  }
}, 300_000);

afterAll(async () => {
  if (work) await rm(work, { recursive: true, force: true });
});

const put = async (path: string, mode = 0o600, content = '{}\n') => {
  await mkdir(dirname(path), { recursive: true, mode: 0o755 });
  await writeFile(path, content);
  await chmod(path, mode);
};

/** An ordinary ~/.copilot (all owner-only) under `dir`. */
async function copilotDir(dir: string): Promise<void> {
  await put(join(dir, 'config.json'));
  await put(join(dir, 'mcp-secrets', 'index.json'));
  await put(join(dir, 'command-history-state', 'history.jsonl'));
  await mkdir(join(dir, 'session-state'), { recursive: true, mode: 0o700 });
  await chmod(dir, 0o700);
}

async function scan(home: string, env: Record<string, string>, extra: string[] = []): Promise<AgentScanResult> {
  const out = join(home, '..', `scan-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  const r = await run(['scan', '-a', 'copilot-cli', '-f', 'json', '-o', out, ...extra], home, env);
  if (r.code > 1) throw new Error(`scan exited ${r.code}: ${r.stderr}`);
  return (JSON.parse(await readFile(out, 'utf-8')) as ScanResult).agents.find(a => a.agent === 'copilot-cli' && a.installation.profile !== 'project')!;
}

async function remote(home: string, env: Record<string, string>): Promise<{ agent: AgentScanResult; snapshot: string }> {
  const manifest = join(home, '..', 'manifest.json');
  const snapshotPath = join(home, '..', 'snapshot.json');
  await writeFile(manifest, (await run(['probe', 'manifest'], home, env)).stdout);
  const p = await run(['--manifest', manifest], home, env, probe!);
  expect(p.code).toBe(0);
  await writeFile(snapshotPath, p.stdout);
  return { agent: await scan(home, env, ['--snapshot', snapshotPath]), snapshot: p.stdout };
}

const verdicts = (a: AgentScanResult) => Object.fromEntries(a.results.map(r => [r.id, `${r.passed ? 'pass' : 'fail'}/${r.severity}/${r.fixable ? 'fixable' : '-'}`]));
const result = (a: AgentScanResult, id: string): CheckResult => a.results.find(r => r.id === id)!;

interface Layout {
  name: string;
  build(base: string, home: string): Promise<Record<string, string>>;
  ghc001: RegExp;
  fixable: boolean;
}

const layouts: Layout[] = [
  {
    name: 'session-state/ linked to ~/.ssh/id_rsa (0644)',
    async build(_base, home) {
      await copilotDir(join(home, '.copilot'));
      await put(join(home, '.ssh', 'id_rsa'), 0o644, '-----BEGIN KEY-----\nAAAA\n-----END KEY-----\n');
      await put(join(home, '.ssh', `${CANARY}-ssh`));
      await rm(join(home, '.copilot', 'session-state'), { recursive: true });
      await symlink(join(home, '.ssh', 'id_rsa'), join(home, '.copilot', 'session-state'));
      return {};
    },
    ghc001: /1 store link\(s\) point into a sensitive location/,
    fixable: false,
  },
  {
    name: '~/.copilot linked out of the home',
    async build(base, home) {
      const out = join(base, 'out', 'cop');
      await copilotDir(out);
      await put(join(out, 'session-state', 'abc', `${CANARY}-out.jsonl`), 0o644);
      await mkdir(home, { recursive: true });
      await symlink(out, join(home, '.copilot'));
      return {};
    },
    ghc001: /is a link out of the home — its private stores there are not checked/,
    fixable: false,
  },
  {
    name: '~/.copilot linked into ~/.aws',
    async build(_base, home) {
      const aws = join(home, '.aws', 'cop');
      await copilotDir(aws);
      await put(join(aws, 'session-state', `${CANARY}-aws.jsonl`), 0o644);
      await symlink(aws, join(home, '.copilot'));
      return {};
    },
    ghc001: /is a link into a sensitive location \(AWS credentials/,
    fixable: false,
  },
  {
    name: 'COPILOT_HOME outside the home',
    async build(base, home) {
      const cp = join(base, 'data', 'cp');
      await copilotDir(cp);
      await put(join(cp, 'session-state', 'abc', 'events.jsonl'), 0o644);
      await mkdir(home, { recursive: true });
      return { COPILOT_HOME: cp };
    },
    ghc001: /not changed by vaso fix: .* is outside the home/,
    fixable: false,
  },
];

describe.each(layouts)('copilot-cli: $name', (layout) => {
  let home: string;
  let env: Record<string, string>;
  let local: AgentScanResult;

  beforeAll(async () => {
    const base = await mkdtemp(join(work, 'case-'));
    await chmod(base, 0o755);
    home = join(base, 'home');
    await mkdir(home, { recursive: true, mode: 0o755 });
    await chmod(home, 0o755);
    env = await layout.build(base, home);
    local = await scan(home, env);
  }, 120_000);

  it('GHC-001 reports it, not offered to vaso fix', () => {
    const r = result(local, 'GHC-001');
    expect(r.passed).toBe(false);
    expect(r.message).toMatch(layout.ghc001);
    expect(Boolean(r.fixable)).toBe(layout.fixable);
    // nothing else offered that vaso fix would refuse
    expect(local.results.filter(x => x.fixable && (!x.passed || x.foldedInto)).map(x => x.id)).toEqual([]);
  });

  it.skipIf(!goAvailable)('a probe snapshot reaches the same verdicts; no name from behind the link ships', async () => {
    const r = await remote(home, env);
    expect(verdicts(r.agent)).toEqual(verdicts(local));
    expect(result(r.agent, 'GHC-001').evidence?.map(e => e.snippet)).toEqual(result(local, 'GHC-001').evidence?.map(e => e.snippet));
    expect(r.snapshot.includes(CANARY)).toBe(false);
    expect(r.snapshot.includes('BEGIN KEY')).toBe(false);
  }, 120_000);

  it('vaso fix changes nothing and exits 0, twice', async () => {
    for (let i = 0; i < 2; i++) {
      const f = await run(['fix', '-a', 'copilot-cli', '-y'], home, env);
      expect(f.code, f.stdout + f.stderr).toBe(0);
    }
    const key = join(home, '.ssh', 'id_rsa');
    if (await stat(key).then(() => true, () => false)) expect((await stat(key)).mode & 0o777).toBe(0o644);
  }, 120_000);
});
