import { describe, expect, it } from 'vitest';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import type { FileEntry } from '../core/snapshot-types.js';
import { MCPDiscovery } from './discovery.js';

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

  it('leaves servers alone without any list', async () => {
    const got = await servers({ [`${HOME}/.claude.json`]: { mcpServers: { a: U } }, [`${HOME}/.gemini/settings.json`]: { mcpServers: { b: U } } });
    expect(got).toEqual({ 'claude-code:a': false, 'gemini-cli:b': false });
  });

  it('drops off-listed servers from a scan discovery', async () => {
    const r = await new MCPDiscovery(fsWith({ [`${HOME}/.gemini/settings.json`]: { mcp: { excluded: ['x'] }, mcpServers: { x: U, y: U } } })).discover('linux');
    expect(r.configs.flatMap(c => c.servers.map(s => s.name))).toEqual(['y']);
  });
});
