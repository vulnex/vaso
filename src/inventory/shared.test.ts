import { describe, expect, it } from 'vitest';
import type { AgentInstallation, AgentType, McpServerItem } from '../core/types.js';
import { findSharedMcpServers, mcpServerKey } from './shared.js';

const npx = (name: string, configFile: string, spec: string, pin: NonNullable<McpServerItem['package']>['pin']): McpServerItem => ({
  name, configFile, scope: 'user', transport: 'stdio', command: 'npx', args: ['-y', spec],
  package: { runner: 'npx', ecosystem: 'npm', name: spec.replace(/@[^@/]*$/, '') || spec, spec, pin },
});

function inst(agent: AgentType, installDir: string, servers: McpServerItem[], agentName?: string, profile?: string): AgentInstallation {
  return { agent, installDir, configFiles: [], ...(agentName ? { agentName } : {}), ...(profile ? { profile } : {}), inventory: { skillsDirs: [], skills: [], otherEntries: [], mcpServers: servers } };
}

describe('mcpServerKey', () => {
  it('keys by package (PyPI names normalized), URL origin + path, or command line', () => {
    expect(mcpServerKey(npx('a', '/c', '@Scope/Pkg@1.0.0', 'exact'))).toBe('npm:@scope/pkg');
    expect(mcpServerKey({ name: 'p', configFile: '/c', scope: 'user', transport: 'stdio', command: 'uvx', package: { runner: 'uvx', ecosystem: 'pypi', name: 'Godot_AI', spec: 'Godot_AI==3.2.5', pin: 'exact' } })).toBe('pypi:godot-ai');
    expect(mcpServerKey({ name: 'r', configFile: '/c', scope: 'user', transport: 'sse', url: 'https://MCP.example.com/sse/?token=***' })).toBe('url:https://mcp.example.com/sse');
    expect(mcpServerKey({ name: 'l', configFile: '/c', scope: 'user', transport: 'stdio', command: '/opt/bin/srv', args: ['--x'] })).toBe('command:/opt/bin/srv --x');
  });
});

describe('findSharedMcpServers', () => {
  it('groups one package configured by several agents and flags it when any of them is unpinned', () => {
    const shared = findSharedMcpServers([
      inst('claude-code', '/h/.claude', [npx('github', '/h/.claude.json', '@modelcontextprotocol/server-github', 'none')]),
      inst('cursor-cli', '/h/.cursor', [npx('gh', '/h/.cursor/mcp.json', '@modelcontextprotocol/server-github@2025.4.8', 'exact')]),
      inst('codex', '/h/.codex', [npx('fs', '/h/.codex/config.toml', '@modelcontextprotocol/server-filesystem@1.0.0', 'exact')]),
    ]);
    expect(shared).toHaveLength(1);
    expect(shared[0]).toMatchObject({ key: 'npm:@modelcontextprotocol/server-github', unpinned: true });
    expect(shared[0].users.map(u => [u.agent, u.server, u.pin])).toEqual([['claude-code', 'github', 'none'], ['cursor-cli', 'gh', 'exact']]);
  });

  it('does not count one file several agents read, or one installation twice', () => {
    const server = npx('x', '/h/.config/devin/mcp_config.json', 'pkg@1.0.0', 'exact');
    expect(findSharedMcpServers([
      inst('devin', '/h/.config/devin', [server]),
      inst('windsurf', '/h/.codeium/windsurf', [server]),
    ])).toEqual([]);
    expect(findSharedMcpServers([
      inst('claude-code', '/h/.claude', [npx('a', '/h/.claude.json', 'pkg@1.0.0', 'exact'), npx('b', '/h/.claude/mcp.json', 'pkg@1.0.0', 'exact')]),
    ])).toEqual([]);
  });

  it('ignores disabled servers', () => {
    const off = { ...npx('github', '/h/.cursor/mcp.json', 'pkg', 'none'), disabled: true };
    expect(findSharedMcpServers([
      inst('claude-code', '/h/.claude', [npx('github', '/h/.claude.json', 'pkg', 'none')]),
      inst('cursor-cli', '/h/.cursor', [off]),
    ])).toEqual([]);
  });

  it('lists unpinned groups first', () => {
    const shared = findSharedMcpServers([
      inst('claude-code', '/h/.claude', [npx('a', '/1', 'aaa@1.0.0', 'exact'), npx('z', '/1', 'zzz', 'none')]),
      inst('codex', '/h/.codex', [npx('a', '/2', 'aaa@1.0.0', 'exact'), npx('z', '/2', 'zzz@latest', 'tag')]),
    ]);
    expect(shared.map(g => [g.key, g.unpinned])).toEqual([['npm:zzz', true], ['npm:aaa', false]]);
  });

  it('keeps a project-scope twin of a user-scope server in the same file, and its pin', () => {
    // ~/.claude.json: `x` pinned at user scope, unpinned for one project
    const shared = findSharedMcpServers([
      inst('claude-code', '/h/.claude', [
        npx('x', '/h/.claude.json', 'pkg@1.0.0', 'exact'),
        { ...npx('x', '/h/.claude.json', 'pkg', 'none'), scope: 'project', project: '/srv/app' },
      ]),
      inst('cursor-cli', '/h/.cursor', [npx('x', '/h/.cursor/mcp.json', 'pkg@1.0.0', 'exact')]),
    ]);
    expect(shared).toHaveLength(1);
    expect(shared[0].unpinned).toBe(true);
    expect(shared[0].users.map(u => [u.agent, u.project, u.pin])).toEqual([
      ['claude-code', undefined, 'exact'], ['claude-code', '/srv/app', 'none'], ['cursor-cli', undefined, 'exact'],
    ]);
  });

  it('carries each installation\'s profile', () => {
    const shared = findSharedMcpServers([
      inst('openclaw', '/h/.openclaw', [npx('s', '/h/.openclaw/openclaw.json', 'shared-mcp-pkg', 'none')]),
      inst('openclaw', '/h/.openclaw-work', [npx('s', '/h/.openclaw-work/openclaw.json', 'shared-mcp-pkg', 'none')], undefined, 'work'),
    ]);
    expect(shared[0].users.map(u => [u.agent, u.profile])).toEqual([['openclaw', undefined], ['openclaw', 'work']]);
  });
});
