import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtemp, mkdir, writeFile, chmod, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { captureConfigLoadErrors, loadConfig } from './config-loader.js';
import { LocalFSProvider } from './local-fs-provider.js';
import { SnapshotFSProvider } from './snapshot-fs-provider.js';
import type { ProbeSnapshot } from './snapshot-types.js';
import type { AgentInstallation, CheckModule, ScanContext } from './types.js';
import type { FSProvider } from './fs-provider.js';
import type { AgentAdapter } from '../adapters/adapter.js';
import { ScanEngine, sourceReadResult } from './engine.js';
import { CheckRegistry } from './check-registry.js';
import { AdapterRegistry } from '../adapters/registry.js';
import { readTextIfPresent } from '../adapters/load-if-present.js';
import { readPlist } from '../adapters/plist-config.js';
import { MCPDiscovery } from '../mcp/discovery.js';
import { resolveServerSources } from '../mcp/source-resolver.js';
import { claudeCodeChecks } from '../checks/claude-code/index.js';
import { codexChecks } from '../checks/codex/index.js';
import { geminiCliChecks as geminiChecks } from '../checks/gemini-cli/index.js';
import { devinChecks } from '../checks/devin/index.js';
import { abacusChecks } from '../checks/abacus/index.js';
import { skillChecks as skillsChecks } from '../checks/skills/index.js';

/**
 * dt19: files that exist but can't be read or parsed must surface — as
 * CONFIG-LOAD (configs, memory/rules/trust files, plists, MCP configs), or
 * as an errored/unverified result (MCP server source, skill files) — never
 * pass as absent.
 */

const canChmod = process.platform !== 'win32' && process.getuid?.() !== 0;

let dir: string;
const local = new LocalFSProvider();

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'vaso-unreadable-'));
});

afterEach(async () => {
  await chmod(dir, 0o755).catch(() => undefined);
  await rm(dir, { recursive: true, force: true });
});

function snapshot(overrides: Partial<ProbeSnapshot>): ProbeSnapshot {
  return {
    version: 1,
    hostname: 'h',
    platform: 'linux',
    homedir: '/home/u',
    timestamp: '2026-11-08T00:00:00Z',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: {},
    directories: {},
    commandOutputs: {},
    env: {},
    ...overrides,
  };
}

function ctxFor(agent: AgentInstallation['agent'], installDir: string, fs: FSProvider, extra: Partial<AgentInstallation> = {}): ScanContext {
  return { installation: { agent, installDir, configFiles: [], ...extra }, configs: [], platform: fs.platform, fs };
}

describe('a directory where a config file is expected', () => {
  it('is a CONFIG-LOAD (EISDIR) locally', async () => {
    const path = join(dir, 'openclaw.json');
    await mkdir(path);
    const { loadErrors } = await captureConfigLoadErrors(() => loadConfig(path, local).catch(() => undefined));
    expect(loadErrors).toEqual([expect.objectContaining({ filePath: path, stage: 'read', message: expect.stringContaining('EISDIR') })]);
  });

  it('reads the same from a snapshot, where only its directory mode was recorded', async () => {
    const fs = new SnapshotFSProvider(snapshot({ directoryModes: { '/home/u/.openclaw': 0o700, '/home/u/.openclaw/openclaw.json': 0o755 } }));
    const path = '/home/u/.openclaw/openclaw.json';
    const { loadErrors } = await captureConfigLoadErrors(() => loadConfig(path, fs).catch(() => undefined));
    expect(loadErrors).toEqual([{ filePath: path, stage: 'read', message: `EISDIR: illegal operation on a directory, read '${path}'` }]);
  });

  it('a missing file is still not an error', async () => {
    const { loadErrors } = await captureConfigLoadErrors(() => loadConfig(join(dir, 'nope.json'), local).catch(() => undefined));
    expect(loadErrors).toEqual([]);
  });
});

describe('readTextIfPresent', () => {
  it.skipIf(!canChmod)('records an unreadable file, not a missing one', async () => {
    const file = join(dir, 'CLAUDE.md');
    await writeFile(file, 'x');
    await chmod(file, 0);
    const { result, loadErrors } = await captureConfigLoadErrors(async () => [
      await readTextIfPresent(file, local),
      await readTextIfPresent(join(dir, 'missing.md'), local),
    ]);
    expect(result).toEqual([undefined, undefined]);
    expect(loadErrors).toEqual([expect.objectContaining({ filePath: file, stage: 'read', message: expect.stringContaining('EACCES') })]);
  });

  it('records a probe-denied snapshot file, never a metadata-only one', async () => {
    const fs = new SnapshotFSProvider(snapshot({
      files: {
        '/home/u/.claude/CLAUDE.md': { content: '', mode: 0o000, exists: true, denied: true },
        '/home/u/.codex/history.jsonl': { content: '', mode: 0o600, exists: true, contentOmitted: true, omitted: 'metadata' },
        // Over the probe's size cap: a local scan reads it, so no error remotely either
        '/home/u/.codex/AGENTS.md': { content: '', mode: 0o600, exists: true, contentOmitted: true, omitted: 'size' },
      },
    }));
    const { loadErrors } = await captureConfigLoadErrors(async () => {
      await readTextIfPresent('/home/u/.claude/CLAUDE.md', fs);
      await readTextIfPresent('/home/u/.codex/history.jsonl', fs);
      await readTextIfPresent('/home/u/.codex/AGENTS.md', fs);
    });
    expect(loadErrors.map(e => e.filePath)).toEqual(['/home/u/.claude/CLAUDE.md']);
  });
});

describe.skipIf(!canChmod)('memory, rules and trust files read by checks (g6-F3, g7-A5, g7-F9)', () => {
  const run = async (check: CheckModule, ctx: ScanContext) => captureConfigLoadErrors(() => check.run(ctx));
  const byId = (list: CheckModule[], id: string) => list.find(c => c.id === id)!;

  it('CC-012 does not say "no memory file" for an unreadable CLAUDE.md', async () => {
    const file = join(dir, 'CLAUDE.md');
    await writeFile(file, 'x');
    await chmod(file, 0);
    const { result, loadErrors } = await run(byId(claudeCodeChecks, 'CC-012'), ctxFor('claude-code', dir, local));
    expect(result.message).not.toMatch(/No CLAUDE\.md/);
    expect(result.message).toMatch(/could not be read/);
    expect(loadErrors.map(e => e.filePath)).toEqual([file]);
  });

  it('CDX-007 and CDX-010 report an unreadable AGENTS.md and .rules file', async () => {
    await writeFile(join(dir, 'AGENTS.md'), 'x');
    await chmod(join(dir, 'AGENTS.md'), 0);
    await mkdir(join(dir, 'rules'));
    await writeFile(join(dir, 'rules', 'default.rules'), 'prefix_rule(pattern=["bash"])');
    await chmod(join(dir, 'rules', 'default.rules'), 0);
    const ctx = ctxFor('codex', dir, local);
    expect((await run(byId(codexChecks, 'CDX-007'), ctx)).loadErrors.map(e => e.filePath)).toEqual([join(dir, 'AGENTS.md')]);
    expect((await run(byId(codexChecks, 'CDX-010'), ctx)).loadErrors.map(e => e.filePath)).toEqual([join(dir, 'rules', 'default.rules')]);
  });

  it('CDX-010 reports a rules directory it cannot list', async () => {
    await mkdir(join(dir, 'rules'));
    await chmod(join(dir, 'rules'), 0);
    const { result, loadErrors } = await run(byId(codexChecks, 'CDX-010'), ctxFor('codex', dir, local));
    expect(result.message).toMatch(/could not be listed/);
    expect(loadErrors.map(e => e.filePath)).toEqual([join(dir, 'rules')]);
    await chmod(join(dir, 'rules'), 0o755);
  });

  it('a snapshot directory known only from its parent listing is empty, not a CONFIG-LOAD', async () => {
    const fs = new SnapshotFSProvider(snapshot({
      files: { '/home/u/.codex/config.toml': { exists: true, mode: 0o600, content: '' } as never },
      directories: { '/home/u/.codex': ['config.toml', 'rules/'] },
      directoryModes: { '/home/u/.codex': 0o700, '/home/u': 0o750 },
    }));
    const { result, loadErrors } = await run(byId(codexChecks, 'CDX-010'), ctxFor('codex', '/home/u/.codex', fs));
    expect(loadErrors).toEqual([]);
    expect(result.message).not.toMatch(/could not be listed/);
  });

  it('GEM-011 reports an unreadable or malformed trustedFolders.json', async () => {
    const file = join(dir, 'trustedFolders.json');
    await writeFile(file, '{ "/": "TRUST_FOLDER", ');
    const fs = new LocalFSProvider();
    const ctx = ctxFor('gemini-cli', dir, fs);
    expect((await run(byId(geminiChecks, 'GEM-011'), ctx)).loadErrors).toEqual([expect.objectContaining({ filePath: file, stage: 'parse' })]);
    await writeFile(file, '{ "/": "TRUST_FOLDER" }');
    await chmod(file, 0);
    expect((await run(byId(geminiChecks, 'GEM-011'), ctx)).loadErrors).toEqual([expect.objectContaining({ filePath: file, stage: 'read' })]);
  });

  it('DEV-008 reports an unreadable trusted_workspaces.json', async () => {
    // $XDG_DATA_HOME/devin/cli/trusted_workspaces.json
    await mkdir(join(dir, 'devin', 'cli'), { recursive: true });
    const file = join(dir, 'devin', 'cli', 'trusted_workspaces.json');
    await writeFile(file, '{"trusted_paths":["/"]}');
    await chmod(file, 0);
    const fs = new LocalFSProvider();
    fs.getEnv = (k: string) => (k === 'XDG_DATA_HOME' ? dir : undefined);
    const { result, loadErrors } = await run(byId(devinChecks, 'DEV-008'), ctxFor('devin', join(dir, 'cfg'), fs));
    expect(result.passed).toBe(true);
    expect(loadErrors.map(e => e.filePath)).toEqual([file]);
  });

  it('ABA-009 reports an unreadable trusted-workspaces.json', async () => {
    await mkdir(join(dir, '.abacusai'));
    const file = join(dir, '.abacusai', 'trusted-workspaces.json');
    await writeFile(file, '{"workspaces":{"/":{}}}');
    await chmod(file, 0);
    const fs = new LocalFSProvider();
    fs.homedir = () => dir;
    const { result, loadErrors } = await run(byId(abacusChecks, 'ABA-009'), ctxFor('abacus', join(dir, '.abacusai'), fs));
    expect(result.passed).toBe(true);
    expect(loadErrors.map(e => e.filePath)).toEqual([file]);
  });
});

describe.skipIf(!canChmod)('the engine reports check-time read failures as CONFIG-LOAD', () => {
  it('once per file, beside the detection-time ones', async () => {
    const memory = join(dir, 'CLAUDE.md');
    await writeFile(memory, 'x');
    await chmod(memory, 0);
    const adapter: AgentAdapter = {
      agent: 'claude-code',
      displayName: 'Claude Code',
      async detect() { return [{ agent: 'claude-code', installDir: dir, configFiles: [] }]; },
      getConfigPaths() { return []; },
      getSkillsDir() { return undefined; },
      getGatewayInfo() { return undefined; },
    };
    const adapters = new AdapterRegistry();
    adapters.register(adapter);
    const checks = new CheckRegistry();
    const cc012 = claudeCodeChecks.find(c => c.id === 'CC-012')!;
    checks.register(cc012);
    // A second check reading the same file must not add a second finding
    checks.register({ ...cc012, id: 'CC-012-COPY' });
    const result = await new ScanEngine(adapters, checks, local).scan({ agentFilter: 'claude-code' });
    const loads = result.agents[0].results.filter(r => r.id === 'CONFIG-LOAD');
    expect(loads).toHaveLength(1);
    expect(loads[0]).toMatchObject({ errored: true, severity: 'warning', name: 'Claude Code Config Load Error' });
    expect(loads[0].evidence?.[0].file).toBe(memory);
    expect(result.agents[0].score).toBeLessThan(100);
  });

  it('once per agent when several installations read the same file', async () => {
    const shared = join(dir, 'CLAUDE.md');
    await writeFile(shared, 'x');
    await chmod(shared, 0);
    const adapter: AgentAdapter = {
      agent: 'claude-code',
      displayName: 'Claude Code',
      async detect() {
        return [
          { agent: 'claude-code', installDir: dir, configFiles: [] },
          { agent: 'claude-code', installDir: join(dir, 'other'), configFiles: [] },
        ];
      },
      getConfigPaths() { return []; },
      getSkillsDir() { return undefined; },
      getGatewayInfo() { return undefined; },
    };
    const adapters = new AdapterRegistry();
    adapters.register(adapter);
    const checks = new CheckRegistry();
    checks.register({
      id: 'X-READ', name: 'Reads the shared file', category: 'config', severity: 'warning', description: '',
      async run(ctx) {
        await readTextIfPresent(shared, ctx.fs);
        return { id: 'X-READ', name: 'Reads the shared file', category: 'config', severity: 'warning', passed: true, message: 'ok' };
      },
    });
    const result = await new ScanEngine(adapters, checks, local).scan({ agentFilter: 'claude-code' });
    expect(result.agents.map(a => a.results.filter(r => r.id === 'CONFIG-LOAD').length)).toEqual([1, 0]);
    expect(result.agents[1].score).toBe(100);
  });
});

describe('plists (g7-A4)', () => {
  const fakeFs = (exitCode: number, stdout: string, stderr = ''): FSProvider => ({
    ...local,
    platform: 'darwin',
    access: async () => true,
    stat: local.stat.bind(local),
    exec: async () => ({ stdout, stderr, exitCode }),
  } as unknown as FSProvider);

  it('records a plist plutil cannot open, or one that is not a dictionary', async () => {
    const path = '/Users/u/Library/Preferences/com.openai.chat.plist';
    const denied = await captureConfigLoadErrors(() => readPlist(path, fakeFs(1, `${path}: (The file couldn’t be opened because you don’t have permission to view it.)`)));
    expect(denied.result).toBeUndefined();
    expect(denied.loadErrors).toEqual([expect.objectContaining({ filePath: path, stage: 'read' })]);
    const scalar = await captureConfigLoadErrors(() => readPlist(path, fakeFs(0, '<?xml version="1.0"?><plist version="1.0"><string>garbage</string></plist>')));
    expect(scalar.loadErrors).toEqual([expect.objectContaining({ filePath: path, stage: 'parse' })]);
  });

  it('a command the snapshot did not collect is not a failure', async () => {
    const { loadErrors } = await captureConfigLoadErrors(() => readPlist('/x.plist', fakeFs(127, '', 'Command not collected in snapshot')));
    expect(loadErrors).toEqual([]);
  });
});

describe('vaso mcp scan discovery (g3-F2)', () => {
  it.skipIf(!canChmod)('reports unreadable, malformed and directory configs — not empty ones', async () => {
    await mkdir(join(dir, '.cursor'));
    await writeFile(join(dir, '.cursor', 'mcp.json'), '{"mcpServers":{"a":{"command":"x"}}}');
    await chmod(join(dir, '.cursor', 'mcp.json'), 0);
    await mkdir(join(dir, '.claude'));
    await writeFile(join(dir, '.claude', 'mcp.json'), '{ "mcpServers": ');
    await mkdir(join(dir, '.copilot', 'mcp-config.json'), { recursive: true });
    await writeFile(join(dir, '.claude.json'), '  \n');
    const fs = new LocalFSProvider();
    fs.homedir = () => dir;
    fs.getEnv = () => undefined;
    const result = await new MCPDiscovery(fs).discover('linux');
    const byPath = Object.fromEntries((result.loadErrors ?? []).map(e => [e.filePath, e]));
    expect(byPath[join(dir, '.cursor', 'mcp.json')]).toMatchObject({ source: 'Cursor', stage: 'read' });
    expect(byPath[join(dir, '.claude', 'mcp.json')]).toMatchObject({ source: 'Claude Code', stage: 'parse' });
    expect(byPath[join(dir, '.copilot', 'mcp-config.json')]?.message).toMatch(/EISDIR/);
    expect(byPath[join(dir, '.claude.json')]).toBeUndefined();
  });

  it('a bare project mcp.json that does not parse is not reported (it may be another tool\'s)', async () => {
    await writeFile(join(dir, 'mcp.json'), '{ not json');
    await mkdir(join(dir, '.cursor'));
    await writeFile(join(dir, '.cursor', 'mcp.json'), '{ "mcpServers": ');
    const fs = new LocalFSProvider();
    fs.homedir = () => join(dir, 'home');
    fs.getEnv = () => undefined;
    const result = await new MCPDiscovery(fs).discover('linux', dir);
    expect((result.loadErrors ?? []).map(e => e.filePath)).toEqual([join(dir, '.cursor', 'mcp.json')]);
  });

  it('the scan carries them as CONFIG-LOAD results', async () => {
    const result = await new ScanEngine(new AdapterRegistry(), new CheckRegistry(), local).scanMCP([], [], {}, [
      { source: 'Cursor', filePath: '/h/.cursor/mcp.json', stage: 'read', message: 'EACCES: permission denied' },
    ]);
    expect(result.agents[0].results).toEqual([expect.objectContaining({ id: 'CONFIG-LOAD', errored: true, name: 'Cursor MCP Config Load Error' })]);
  });
});

describe.skipIf(!canChmod)('unreadable local MCP server source (g3-F3)', () => {
  it('is recorded and reported as SOURCE-READ, like PACKAGE-RESOLVE', async () => {
    const server = join(dir, 'server.js');
    await writeFile(server, 'console.log(1)');
    await chmod(server, 0);
    const pkgDir = join(dir, 'pkg');
    await mkdir(pkgDir);
    await chmod(pkgDir, 0);
    const sources = await resolveServerSources([
      { name: 'file', command: 'node', args: [server], transport: 'stdio' },
      { name: 'dir', command: 'node', args: [pkgDir], transport: 'stdio' },
    ]);
    expect(sources.map(s => [s.serverName, s.sourceCode, s.readFailure?.slice(0, 6)])).toEqual([
      ['file', undefined, 'EACCES'],
      ['dir', undefined, 'EACCES'],
    ]);
    const result = sourceReadResult(sources);
    expect(result).toMatchObject({ id: 'SOURCE-READ', errored: true, passed: false });
    expect(result?.evidence).toHaveLength(2);
    await chmod(pkgDir, 0o755);
  });
});

describe.skipIf(!canChmod)('unreadable skill file (g7-S9)', () => {
  it('SKL-002 reports it instead of skipping it', async () => {
    const skill = join(dir, 'skills', 'tool');
    await mkdir(skill, { recursive: true });
    await writeFile(join(skill, 'SKILL.md'), '# tool');
    await writeFile(join(skill, 'run.js'), 'eval(x)');
    await chmod(join(skill, 'run.js'), 0);
    const ctx: ScanContext = {
      ...ctxFor('claude-code', dir, local, { skillsDir: join(dir, 'skills') }),
      skillFiles: [join(skill, 'SKILL.md'), join(skill, 'run.js')],
    };
    const result = await skillsChecks.find(c => c.id === 'SKL-002')!.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.evidence).toEqual([expect.objectContaining({ file: join(skill, 'run.js'), detail: expect.stringContaining("can't be read") })]);
  });
});
