import { describe, expect, it } from 'vitest';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import type { FileEntry } from '../core/snapshot-types.js';
import { MCPDiscovery } from './discovery.js';
import { expandClaudeVars, urlMatches } from './off-lists.js';
import type { AgentType, ParsedConfig, ScanContext } from '../core/types.js';
import { cc005 } from '../checks/claude-code/cc-005-unpinned-mcp.js';
import { gem007 } from '../checks/gemini-cli/gem-007-unpinned-mcp.js';
import { gem008 } from '../checks/gemini-cli/gem-008-mcp-http.js';
import { qc004 } from '../checks/qwen-code/qc-004-mcp-trust.js';
import { qc006 } from '../checks/qwen-code/qc-006-unpinned-mcp.js';

const HOME = '/home/u';
const PROJ = '/work/app';
const U = { command: 'npx', args: ['-y', 'some-unpinned-mcp'] };

function fsWith(files: Record<string, unknown>): SnapshotFSProvider {
  const entries: Record<string, FileEntry> = {};
  for (const [p, v] of Object.entries(files)) entries[p] = { content: JSON.stringify(v), mode: 0o100644, exists: true };
  return new SnapshotFSProvider({
    version: 1, hostname: 'h', platform: 'linux', homedir: HOME, timestamp: 't',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: entries, directories: {}, commandOutputs: {}, env: {},
  });
}

async function servers(files: Record<string, unknown>, projectDir?: string): Promise<Record<string, boolean>> {
  const r = await new MCPDiscovery(fsWith(files)).discover('linux', projectDir, { includeDisabled: true });
  return Object.fromEntries(r.configs.flatMap(c => c.servers.map(s => [`${c.agents?.join('+')}:${s.name}`, s.disabled === true])));
}

describe('MCP off lists', () => {
  it('Claude Code: deniedMcpServers, disabledMcpjsonServers and a project\'s disabledMcpServers', async () => {
    const got = await servers({
      [`${HOME}/.claude/settings.json`]: { disabledMcpjsonServers: ['rejected'], deniedMcpServers: [{ serverName: 'denied' }, { serverCommand: ['npx', '-y', 'bad'] }] },
      [`${HOME}/.claude.json`]: {
        mcpServers: { denied: U, ok: U, cmd: { command: 'npx', args: ['-y', 'bad'] } },
        projects: { [PROJ]: { mcpServers: { localoff: U, localon: U }, disabledMcpServers: ['localoff'] } },
      },
      [`${PROJ}/.mcp.json`]: { mcpServers: { rejected: U } },
    }, PROJ);
    expect(got).toMatchObject({
      'claude-code:denied': true, 'claude-code:ok': false, 'claude-code:cmd': true,
      'claude-code:localoff': true, 'claude-code:localon': false,
      // Copilot CLI reads the project .mcp.json too and has no such list: still launched there
      'claude-code+copilot-cli:rejected': false,
    });
  });

  it('Claude Code: an allowlist blocks the rest; managed-mcp.json takes exclusive control', async () => {
    const allow = await servers({
      [`${HOME}/.claude/settings.json`]: { allowedMcpServers: [{ serverUrl: 'https://mcp.example.com/*' }, { serverName: 'named' }] },
      [`${HOME}/.claude.json`]: { mcpServers: { remote: { url: 'https://mcp.example.com/mcp', type: 'http' }, other: { url: 'https://x.test/mcp', type: 'http' }, named: U } },
    });
    expect(allow).toMatchObject({ 'claude-code:remote': false, 'claude-code:other': true, 'claude-code:named': false });

    const exclusive = await servers({
      '/etc/claude-code/managed-mcp.json': { mcpServers: {} },
      [`${HOME}/.claude.json`]: { mcpServers: { mine: U } },
    });
    expect(exclusive['claude-code:mine']).toBe(true);
  });

  it('Gemini CLI: mcp.excluded, mcp.allowed and /mcp disable state', async () => {
    const got = await servers({
      [`${HOME}/.gemini/settings.json`]: { mcp: { excluded: ['offgem'] }, mcpServers: { offgem: U, enablementoff: U, on: U } },
      [`${HOME}/.gemini/mcp-server-enablement.json`]: { EnablementOff: { enabled: false } },
    });
    expect(got).toEqual({ 'gemini-cli:offgem': true, 'gemini-cli:enablementoff': true, 'gemini-cli:on': false });

    const allowed = await servers({ [`${HOME}/.gemini/settings.json`]: { mcp: { allowed: ['on'] }, mcpServers: { on: U, other: U } } });
    expect(allowed).toEqual({ 'gemini-cli:on': false, 'gemini-cli:other': true });
  });

  it('Qwen Code: mcp.excluded globs win over mcp.allowed', async () => {
    const got = await servers({
      [`${HOME}/.qwen/settings.json`]: { mcp: { allowed: ['off*', 'keep'], excluded: ['offqwen', 'offglob-*'] }, mcpServers: { offqwen: U, 'offglob-x': U, offthird: U, keep: U, stray: U } },
    });
    expect(got).toEqual({ 'qwen-code:offqwen': true, 'qwen-code:offglob-x': true, 'qwen-code:offthird': false, 'qwen-code:keep': false, 'qwen-code:stray': true });
  });

  it('Qwen Code: an allowed name or glob with an astral character keeps its server on', async () => {
    const exact = await servers({ [`${HOME}/.qwen/settings.json`]: { mcp: { allowed: ['srv-😀', 'gh'] }, mcpServers: { 'srv-😀': U, gh: U, other: U } } });
    expect(exact).toEqual({ 'qwen-code:srv-😀': false, 'qwen-code:gh': false, 'qwen-code:other': true });
    const glob = await servers({ [`${HOME}/.qwen/settings.json`]: { mcp: { allowed: ['*😀*', 'srv-?x'] }, mcpServers: { 'srv-😀': U, 'srv-😁x': U, other: U } } });
    expect(glob).toEqual({ 'qwen-code:srv-😀': false, 'qwen-code:srv-😁x': false, 'qwen-code:other': true });
  });

  it('leaves servers alone without any list', async () => {
    const got = await servers({ [`${HOME}/.claude.json`]: { mcpServers: { a: U } }, [`${HOME}/.gemini/settings.json`]: { mcpServers: { b: U } } });
    expect(got).toEqual({ 'claude-code:a': false, 'gemini-cli:b': false });
  });

  it('drops off-listed servers from a scan discovery', async () => {
    const r = await new MCPDiscovery(fsWith({ [`${HOME}/.gemini/settings.json`]: { mcp: { excluded: ['x'] }, mcpServers: { x: U, y: U } } })).discover('linux');
    expect(r.configs.flatMap(c => c.servers.map(s => s.name))).toEqual(['y']);
  });
});

describe('agent MCP checks honour the off lists', () => {
  // Snapshot scans read no project folder: give project-scope cases a project root explicitly
  function ctxFor(agent: AgentType, files: Record<string, unknown>, configPaths: string[]): ScanContext {
    const fs = fsWith(files);
    const configs: ParsedConfig[] = configPaths.map(p => ({ filePath: p, format: 'json', raw: JSON.stringify(files[p]), data: files[p] as Record<string, unknown> }));
    return { installation: { agent, installDir: HOME, configFiles: configs }, configs, platform: 'linux', fs };
  }
  const snippets = (r: { evidence?: Array<{ snippet?: string }> }) => (r.evidence ?? []).map(e => e.snippet?.split(':')[0]);

  it('CC-005 skips denied servers and a project\'s disabledMcpServers; reports the rest', async () => {
    const files = {
      [`${HOME}/.claude/settings.json`]: { deniedMcpServers: [{ serverName: 'denied' }] },
      [`${HOME}/.claude.json`]: {
        mcpServers: { denied: U, on: U },
        projects: { [PROJ]: { mcpServers: { localoff: U, localon: U }, disabledMcpServers: ['localoff'] } },
      },
    };
    const r = await cc005.run(ctxFor('claude-code', files, [`${HOME}/.claude.json`]));
    expect(snippets(r).sort()).toEqual(['mcpServers.on', `projects[${PROJ}].mcpServers.localon`]);
  });

  it('CC-005 skips project .mcp.json servers rejected by disabledMcpjsonServers', async () => {
    const files = {
      [`${HOME}/.claude/settings.json`]: { disabledMcpjsonServers: ['rejected'] },
      [`${PROJ}/.mcp.json`]: { mcpServers: { rejected: U, accepted: U } },
    };
    expect(snippets(await cc005.run(ctxFor('claude-code', files, [`${PROJ}/.mcp.json`])))).toEqual(['mcpServers.accepted']);
  });

  it('CC-005: Claude Code has no per-entry switch — a "disabled" entry still runs', async () => {
    const files = { [`${HOME}/.claude.json`]: { mcpServers: { x: { ...U, disabled: true } } } };
    expect((await cc005.run(ctxFor('claude-code', files, [`${HOME}/.claude.json`]))).passed).toBe(false);
  });

  it('GEM-007/GEM-008 skip excluded and /mcp-disabled servers', async () => {
    const files = {
      [`${HOME}/.gemini/settings.json`]: {
        mcp: { excluded: ['offgem', 'offhttp'] },
        mcpServers: { offgem: U, enablementoff: U, on: U, offhttp: { url: 'http://mcp.example.com/mcp' } },
      },
      [`${HOME}/.gemini/mcp-server-enablement.json`]: { enablementoff: { enabled: false } },
    };
    const ctx = ctxFor('gemini-cli', files, [`${HOME}/.gemini/settings.json`]);
    expect(snippets(await gem007.run(ctx))).toEqual(['mcpServers.on']);
    expect((await gem008.run(ctx)).passed).toBe(true);
  });

  it('QC-004/QC-006 skip servers mcp.excluded globs switch off', async () => {
    const files = {
      [`${HOME}/.qwen/settings.json`]: {
        mcp: { excluded: ['offqwen', 'offglob-*'] },
        mcpServers: { offqwen: U, 'offglob-x': { ...U, trust: true }, keep: U },
      },
    };
    const ctx = ctxFor('qwen-code', files, [`${HOME}/.qwen/settings.json`]);
    expect(snippets(await qc006.run(ctx))).toEqual(['mcpServers.keep']);
    expect((await qc004.run(ctx)).passed).toBe(true);
  });
});

describe('Hermes YAML 1.1 switches', () => {
  it('marks enabled: no / off servers disabled in discovery', async () => {
    const fs = new SnapshotFSProvider({
      version: 1, hostname: 'h', platform: 'linux', homedir: HOME, timestamp: 't',
      privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
      files: { [`${HOME}/.hermes/config.yaml`]: { content: 'mcp_servers:\n  a:\n    command: node\n    enabled: no\n  b:\n    command: node\n    enabled: off\n  c:\n    command: node\n', mode: 0o100644, exists: true } },
      directories: {}, commandOutputs: {}, env: {},
    });
    const r = await new MCPDiscovery(fs).discover('linux', undefined, { includeDisabled: true });
    const hermes = r.configs.find(c => c.source === 'Hermes')!;
    expect(hermes.servers.map(s => [s.name, s.disabled === true])).toEqual([['a', true], ['b', true], ['c', false]]);
  });
});

/** A snapshot with raw file text and environment. */
function fsRaw(files: Record<string, unknown>, text: Record<string, string> = {}, env: Record<string, string> = {}): SnapshotFSProvider {
  const entries: Record<string, FileEntry> = {};
  for (const [p, v] of Object.entries(files)) entries[p] = { content: JSON.stringify(v), mode: 0o100644, exists: true };
  for (const [p, c] of Object.entries(text)) entries[p] = { content: c, mode: 0o100644, exists: true };
  return new SnapshotFSProvider({
    version: 1, hostname: 'h', platform: 'linux', homedir: HOME, timestamp: 't',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: ['u'], skippedPaths: [] },
    files: entries, directories: {}, commandOutputs: {}, env,
  });
}

describe('Claude Code serverUrl patterns', () => {
  const cases: Array<[string, string, boolean]> = [
    // `*` stays inside the host
    ['*://*.bad.example.com/*', 'http://good.example.org/x.bad.example.com/mcp', false],
    ['*://*.bad.example.com/*', 'https://api.bad.example.com/mcp', true],
    ['https://*.example.com/*', 'https://a.b.example.com:8443/mcp', true],
    // host case-insensitive, trailing dot ignored; path case-sensitive
    ['https://Mcp.Example.com/*', 'https://mcp.example.com/api', true],
    ['https://mcp.example.com./api', 'https://MCP.example.com/api', true],
    ['https://mcp.example.com/API', 'https://mcp.example.com/api', false],
    // no path = any path; a path must match whole
    ['https://mcp.example.com', 'https://mcp.example.com/any/path', true],
    ['https://mcp.example.com/mcp', 'https://mcp.example.com/mcp/extra', false],
    // ports: written-out host = default port only; `*` host or `:*` = every port
    ['https://mcp.example.com/*', 'https://mcp.example.com:8443/api', false],
    ['https://mcp.example.com/*', 'https://mcp.example.com:443/api', true],
    ['https://mcp.example.com:*/*', 'https://mcp.example.com:8443/api', true],
    ['https://mcp.example.com:8443/*', 'https://mcp.example.com:8443/api', true],
    ['https://mcp.example.com:8443/*', 'https://mcp.example.com/api', false],
    ['http://localhost:*/*', 'http://localhost:3000/mcp', true],
    ['*://mcp.example.com/*', 'http://mcp.example.com/mcp', true],
    ['*://mcp.example.com/*', 'http://mcp.example.com:8080/mcp', false],
    ['https://mcp.example.com/*', 'http://mcp.example.com/mcp', false],
    ['https://mcp.example.com/*', 'not a url', false],
  ];
  for (const [pattern, url, want] of cases) {
    it(`${pattern} ${want ? 'matches' : 'does not match'} ${url}`, () => {
      expect(urlMatches(pattern, url)).toBe(want);
    });
  }

  it('a deny URL pattern does not hide a server on another host', async () => {
    const got = await servers({
      [`${HOME}/.claude/settings.json`]: { deniedMcpServers: [{ serverUrl: '*://*.bad.example.com/*' }] },
      [`${HOME}/.claude.json`]: { mcpServers: {
        web1: { type: 'http', url: 'http://good.example.org/x.bad.example.com/mcp' },
        web2: { type: 'http', url: 'https://evil.bad.example.com/mcp' },
      } },
    });
    expect(got).toEqual({ 'claude-code:web1': false, 'claude-code:web2': true });
  });
});

describe('Claude Code ${VAR} in policy entries', () => {
  it('expands both sides before comparing', async () => {
    const fs = fsRaw({
      [`${HOME}/.claude/settings.json`]: { allowedMcpServers: [{ serverCommand: ['${HOME}/bin/srv'] }, { serverUrl: 'https://${MCP_HOST}/*' }] },
      [`${HOME}/.claude.json`]: { mcpServers: {
        literal: { command: `${HOME}/bin/srv` },
        ref: { command: '${HOME}/bin/srv' },
        other: { command: '/opt/other' },
        remote: { type: 'http', url: 'https://mcp.corp.test/mcp' },
        remoteOther: { type: 'http', url: 'https://x.test/mcp' },
      } },
    }, {}, { MCP_HOST: 'mcp.corp.test' });
    const r = await new MCPDiscovery(fs).discover('linux', undefined, { includeDisabled: true });
    const got = Object.fromEntries(r.configs.flatMap(c => c.servers.map(s => [s.name, s.disabled === true])));
    expect(got).toEqual({ literal: false, ref: false, other: true, remote: false, remoteOther: true });
  });

  it('expandClaudeVars: default values, HOME from the scanned home, unknown left as written', () => {
    const fs = fsRaw({});
    expect(expandClaudeVars('${HOME}/x', fs, HOME)).toBe(`${HOME}/x`);
    expect(expandClaudeVars('${NOPE:-/d}/x', fs, HOME)).toBe('/d/x');
    expect(expandClaudeVars('${NOPE}/x', fs, HOME)).toBe('${NOPE}/x');
  });
});

describe('Claude Code managed-mcp.json', () => {
  const MANAGED = '/etc/claude-code/managed-mcp.json';

  it('discovers its servers and switches off the user\'s', async () => {
    const got = await servers({
      [MANAGED]: { mcpServers: { corp: U } },
      [`${HOME}/.claude.json`]: { mcpServers: { mine: U } },
    });
    expect(got).toEqual({ 'claude-code:corp': false, 'claude-code:mine': true });
  });

  it('its servers still honour deniedMcpServers, and skip the allowlist unless they use ${VAR} outside env', async () => {
    const got = await servers({
      [`${HOME}/.claude/settings.json`]: {
        deniedMcpServers: [{ serverName: 'blocked' }],
        allowedMcpServers: [{ serverName: 'nothing-else' }],
      },
      [MANAGED]: { mcpServers: {
        blocked: U,
        plain: U,
        envOnly: { ...U, env: { TOKEN: '${TOKEN}' } },
        varArgs: { command: 'npx', args: ['-y', '${PKG}'] },
      } },
    });
    expect(got).toEqual({
      'claude-code:blocked': true, 'claude-code:plain': false,
      'claude-code:envOnly': false, 'claude-code:varArgs': true,
    });
  });

  it('a managed-mcp.json that does not parse takes no exclusive control', async () => {
    const fs = fsRaw({ [`${HOME}/.claude.json`]: { mcpServers: { mine: U } } }, { [MANAGED]: '{ "mcpServers": { "corp": ' });
    const r = await new MCPDiscovery(fs).discover('linux', undefined, { includeDisabled: true });
    const mine = r.configs.flatMap(c => c.servers).find(s => s.name === 'mine');
    expect(mine?.disabled).toBeUndefined();
    expect(r.loadErrors?.map(e => e.filePath)).toEqual([MANAGED]);
  });

  it('CC-005 judges the managed servers and skips the user\'s', async () => {
    const files: Record<string, unknown> = {
      [MANAGED]: { mcpServers: { corp: U } },
      [`${HOME}/.claude.json`]: { mcpServers: { mine: U } },
    };
    const fs = fsWith(files);
    const configs: ParsedConfig[] = [MANAGED, `${HOME}/.claude.json`].map(p => ({ filePath: p, format: 'json', raw: JSON.stringify(files[p]), data: files[p] as Record<string, unknown> }));
    const r = await cc005.run({ installation: { agent: 'claude-code', installDir: HOME, configFiles: configs }, configs, platform: 'linux', fs });
    expect((r.evidence ?? []).map(e => [e.file, e.snippet?.split(':')[0]])).toEqual([[MANAGED, 'mcpServers.corp']]);
  });
});
