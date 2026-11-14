import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmod, cp, mkdtemp, readdir, readFile, rm, writeFile, lstat } from 'node:fs/promises';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
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
 *   info     [ "<check id>" ] — may be reported, but at info severity at most
 *            (a fixed false positive that stays as advice)
 *   fix      { "resolves": [ids] } — `vaso fix -y` resolves them without
 *            breaking any other check, and `--rollback` restores every file
 *   mcpConfig  path under home of an MCP config: run `vaso mcp scan -p` on it
 *            (agent `mcp`; local only, no probe comparison or fix)
 *   parity   false to skip the probe-snapshot comparison (default: compared
 *            whenever Go is available to build the probe)
 *   cleanIgnore  check ids `clean` doesn't count — checks that read the host
 *            rather than the fixture (app bundles in /Applications, codesign).
 *            Advisory (ADV-*) results are never counted by `clean`: they
 *            follow the version of whatever agent binary the host has
 *   reachable true: the home lives where other users can reach it (/tmp,
 *            755) — a permission finding behind a private temp dir is
 *            mitigated and has nothing to fix
 *   modes    { "<path under home>": "600" } — git keeps only 644/755 file
 *            modes and none for directories, so permissions are set here
 *   localOnly  check ids whose evidence names a path the remote probe never
 *            collects (an MCP server's command outside the manifest): their
 *            links in the MCP inventory are compared on local scans only
 *   env      { "<NAME>": "<value>" } — extra environment for the scan, the
 *            probe and the fix ({{HOME}} substituted), e.g. a relocated
 *            system directory such as HERMES_MANAGED_DIR
 *
 * Scans run with a minimal environment (no real HOME, PATH without agent
 * CLIs) from inside the fixture, so results depend on the fixture only.
 */

const ROOT = resolve(import.meta.dirname, '../..');
const CLI = join(ROOT, 'dist/cli.js');
const CASES = join(ROOT, 'testing/golden/cases');

interface GoldenCase {
  /** `vaso mcp scan` instead of `scan -a`: config paths under home (`-p`) and
   *  server source paths (`--source`). agent must be "mcp"; no parity/fix. */
  mcp?: { paths?: string[]; source?: string[] };
  agent: string;
  source: string;
  clean?: boolean;
  fail?: Record<string, Severity | 'any'>;
  pass?: string[];
  info?: string[];
  fix?: { resolves: string[] };
  parity?: boolean;
  mcpConfig?: string;
  cleanIgnore?: string[];
  modes?: Record<string, string>;
  env?: Record<string, string>;
  localOnly?: string[];
  reachable?: boolean;
  /** Skip on these platforms (fixtures relying on POSIX modes). */
  skipOn?: NodeJS.Platform[];
  /** Expected inventory: skill names, names of other entries, MCP server names. */
  inventory?: { skills: string[]; otherEntries?: string[]; mcpServers?: string[] };
}

/** `mcpConfig: "<path>"` is shorthand for `mcp: { paths: ["<path>"] }`. */
function mcpOf(spec: GoldenCase): GoldenCase['mcp'] {
  return spec.mcp ?? (spec.mcpConfig ? { paths: [spec.mcpConfig] } : undefined);
}

const caseNames = existsSync(CASES)
  ? readdirSync(CASES).filter(n => existsSync(join(CASES, n, 'case.json'))).sort()
  : [];

/** Each case's extra environment, by fixture HOME. */
const caseEnv = new Map<string, Record<string, string>>();

function run(args: string[], home: string, cmd = process.execPath): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((done, fail) => {
    const child = spawn(cmd, cmd === process.execPath ? [CLI, ...args] : args, {
      cwd: home,
      env: { HOME: home, PATH: '/usr/bin:/bin', NO_COLOR: '1', VASO_SKIP_IOC_UPDATE: '1', TMPDIR: tmpdir(), ...caseEnv.get(home) },
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

async function scan(home: string, agent: string, extra: string[] = [], mcp?: GoldenCase['mcp']): Promise<ScanResult> {
  const out = join(home, '..', `scan-${Date.now()}-${Math.random().toString(36).slice(2)}.json`);
  const args = mcp
    ? ['mcp', 'scan', '-f', 'json', '-o', out,
      ...(mcp.paths?.length ? ['-p', ...mcp.paths.map(p => join(home, p))] : []),
      ...(mcp.source?.length ? ['--source', ...mcp.source.map(p => join(home, p))] : [])]
    : ['scan', '-a', agent, '-f', 'json', '-o', out, ...extra];
  const r = await run(args, home);
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
    const reachable = spec.reachable && process.platform !== 'win32';
    work = await mkdtemp(join(reachable ? '/tmp' : tmpdir(), `vaso-golden-${name}-`));
    if (reachable) await chmod(work, 0o755);
    home = join(work, 'home');
    await materialize(join(CASES, name, 'home'), home);
    for (const [path, mode] of Object.entries(spec.modes ?? {})) await chmod(join(home, path), parseInt(mode, 8));
    if (spec.env) caseEnv.set(home, Object.fromEntries(Object.entries(spec.env).map(([k, v]) => [k, v.split('{{HOME}}').join(home)])));
    local = (await scan(home, spec.agent, [], mcpOf(spec))).agents.filter(a => a.agent === spec.agent);
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
    for (const id of spec.info ?? []) {
      const severe = results.filter(r => r.id === id && !r.passed && r.severity !== 'info');
      expect(severe.map(r => `${r.severity}: ${r.message}`), `${id} should be info at most`).toEqual([]);
    }
    if (spec.inventory) {
      const inv = local[0].installation.inventory;
      expect(inv?.skills.map(s => s.name).sort(), 'inventory skills').toEqual([...spec.inventory.skills].sort());
      expect(inv?.otherEntries.map(e => basename(e.path)).sort(), 'inventory other entries').toEqual([...(spec.inventory.otherEntries ?? [])].sort());
      if (spec.inventory.mcpServers) {
        expect(inv?.mcpServers?.map(s => s.name).sort(), 'inventory MCP servers').toEqual([...spec.inventory.mcpServers].sort());
      }
    }
    if (spec.clean) {
      const ignored = new Set(spec.cleanIgnore ?? []);
      const flagged = results.filter(r => r.category !== 'advisory' && !ignored.has(r.id)
        && (r.errored || (!r.passed && SEVERE.has(r.severity))));
      expect(flagged.map(r => `${r.id} ${r.severity}: ${r.message}`), 'vendor-secure config flagged').toEqual([]);
    }
  });

  it.skipIf(skip || spec.parity === false || Boolean(mcpOf(spec)) || !goAvailable)('remote (probe snapshot) reaches the same verdicts', async () => {
    const manifest = join(work, 'manifest.json');
    const snapshot = join(work, 'snapshot.json');
    await writeFile(manifest, (await run(['probe', 'manifest'], home)).stdout);
    const p = await run(['--manifest', manifest], home, probe!);
    expect(p.code).toBe(0);
    await writeFile(snapshot, p.stdout);
    const remote = (await scan(home, spec.agent, ['--snapshot', snapshot])).agents.filter(a => a.agent === spec.agent);
    const key = (as: AgentScanResult[]) => Object.fromEntries(as.map(a => [a.installation.installDir, verdicts(a)]));
    expect(key(remote)).toEqual(key(local));
    // The skill inventory too — descriptions aside: the probe disguises
    // secrets in what it ships, so a masked description may differ
    const localOnly = new Set(spec.localOnly ?? []);
    const inventory = (as: AgentScanResult[]) => Object.fromEntries(as.map(a => {
      const inv = a.installation.inventory;
      const servers = inv?.mcpServers?.map(({ findings, ...s }) => {
        const kept = (findings ?? []).filter(id => !localOnly.has(id));
        return kept.length > 0 ? { ...s, findings: kept } : s;
      });
      return [a.installation.installDir, inv && {
        ...inv,
        skills: inv.skills.map(({ description: _d, ...s }) => s),
        ...(servers ? { mcpServers: servers } : {}),
      }];
    }));
    expect(inventory(remote)).toEqual(inventory(local));
  }, 120_000);

  it.skipIf(skip || !spec.fix || Boolean(mcpOf(spec)))('fix resolves the findings without breaking others, and rollback restores every file', async () => {
    const before = await treeHash(home, join(home, '.vaso'));
    const fixed = await run(['fix', '-a', spec.agent, '-y'], home);
    expect(fixed.code, fixed.stdout + fixed.stderr).toBe(0);

    const after = (await scan(home, spec.agent)).agents.filter(a => a.agent === spec.agent);
    const afterResults = after.flatMap(a => a.results);
    for (const id of spec.fix!.resolves) {
      expect(afterResults.filter(r => r.id === id && !r.passed).map(r => r.message), `${id} after fix`).toEqual([]);
    }
    // A fix must not make another check fail (or error) that passed before
    // on the same installation
    const passedBefore = new Set(local.flatMap(a => a.results.filter(r => r.passed).map(r => `${a.installation.installDir}\0${r.id}`)));
    const broken = after.flatMap(a => a.results
      .filter(r => passedBefore.has(`${a.installation.installDir}\0${r.id}`) && (!r.passed || r.errored))
      .map(r => `${a.installation.installDir}: ${r.id}: ${r.message}`));
    expect(broken, 'checks broken by the fix').toEqual([]);

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
