import { afterEach, describe, expect, it } from 'vitest';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AgentInstallation, AgentType } from '../core/types.js';
import type { MCPConfig } from '../mcp/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { assignMcpServers, attachMcpInventories, inventoriedAgents, mcpServerItem } from './mcp.js';

const HOME = '/home/u';
const inventoried = new Set<AgentType>(['claude-code', 'copilot-cli', 'openclaw', 'devin', 'windsurf', 'cursor-cli']);

function inst(agent: AgentType, installDir: string, extra: Partial<AgentInstallation> = {}): AgentInstallation {
  return { agent, installDir, configFiles: [], ...extra };
}

function config(filePath: string, agents: AgentType[], names: string[], extra: Partial<MCPConfig> = {}): MCPConfig {
  return { source: 'test', filePath, agents, servers: names.map(name => ({ name, command: 'node', args: ['s.js'], transport: 'stdio' as const })), ...extra };
}

describe('mcpServerItem', () => {
  it('keeps env and header names only, masks URL and argv credentials, and reads the runner package', () => {
    const item = mcpServerItem(
      { source: 'x', filePath: '/c.json', servers: [] },
      {
        name: 'db',
        command: 'npx',
        args: ['-y', '@acme/db-mcp@^1.2', '--password', 'Xk9#mPq2vL8wR4tZ'],
        env: { DB_TOKEN: 'secret-env-value', A: '1' },
        headers: { Authorization: 'Bearer abcdefghijklmnop' },
        transport: 'stdio',
      },
    );
    expect(item.envNames).toEqual(['A', 'DB_TOKEN']);
    expect(item.headerNames).toEqual(['Authorization']);
    expect(item.package).toEqual({ runner: 'npx', ecosystem: 'npm', name: '@acme/db-mcp', spec: '@acme/db-mcp@^1.2', pin: 'range' });
    expect(JSON.stringify(item)).not.toContain('secret-env-value');
    expect(JSON.stringify(item)).not.toContain('abcdefghijklmnop');
    expect(JSON.stringify(item)).not.toContain('Xk9#mPq2vL8wR4tZ');
    expect(item.scope).toBe('user');

    const remote = mcpServerItem(
      { source: 'x', filePath: '/c.json', servers: [], scope: 'project', projectRoot: '/p' },
      { name: 'r', url: 'https://api.example.com/mcp?api_key=sk-live-1234567890abcdef', transport: 'streamable-http' },
    );
    expect(remote.url).not.toContain('sk-live-1234567890abcdef');
    expect(remote).toMatchObject({ scope: 'project', project: '/p', transport: 'streamable-http' });
  });
});

describe('mcpServerItem — masked at the source', () => {
  it('masks secrets in the command, the server name and a URL package spec', () => {
    const tok = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
    const item = mcpServerItem(
      { source: 'x', filePath: '/c.json', servers: [] },
      { name: tok, command: `/opt/tool --token=${tok}`, args: ['--from', `git+https://${tok}@github.com/o/r.git`, 'srv'], transport: 'stdio' },
    );
    expect(JSON.stringify(item)).not.toContain('A1b2C3d4E5f6');
  });
});

describe('assignMcpServers', () => {
  it('gives a user config to the agent that loads it, and files no agent owns to the host', () => {
    const cc = inst('claude-code', `${HOME}/.claude`);
    const { byInstallation, host } = assignMcpServers([cc], [
      config(`${HOME}/.claude.json`, ['claude-code'], ['a']),
      config(`${HOME}/.config/Code/User/mcp.json`, [], ['vs']),
      config(`${HOME}/.cursor/mcp.json`, ['cursor-cli'], ['not-installed']),
    ], { home: HOME, inventoried });
    expect(byInstallation.get(cc)!.map(s => s.name)).toEqual(['a']);
    expect(host.map(s => s.name)).toEqual(['vs']);
  });

  it('gives a project config to the project installation under its root, else to the user installation', () => {
    const user = inst('claude-code', `${HOME}/.claude`);
    const proj = inst('claude-code', '/work/app/.claude', { profile: 'project', agentName: 'project:app' });
    const { byInstallation } = assignMcpServers([user, proj], [
      config('/work/app/.mcp.json', ['claude-code'], ['here'], { scope: 'project', projectRoot: '/work/app' }),
      config(`${HOME}/.claude.json`, ['claude-code'], ['elsewhere'], { scope: 'project', projectRoot: '/other' }),
    ], { home: HOME, inventoried, projectDir: '/work/app' });
    expect(byInstallation.get(proj)!.map(s => s.name)).toEqual(['here']);
    expect(byInstallation.get(user)!.map(s => s.name)).toEqual(['elsewhere']);
  });

  it('gives a file several agents read to each of them', () => {
    const devin = inst('devin', `${HOME}/.config/devin`);
    const windsurf = inst('windsurf', `${HOME}/.codeium/windsurf`);
    const { byInstallation } = assignMcpServers([devin, windsurf], [
      config(`${HOME}/.config/devin/mcp_config.json`, ['devin', 'windsurf'], ['shared']),
    ], { home: HOME, inventoried });
    expect(byInstallation.get(devin)!.map(s => s.name)).toEqual(['shared']);
    expect(byInstallation.get(windsurf)!.map(s => s.name)).toEqual(['shared']);
  });

  it('picks the closest installation (OpenClaw profile) and prefers the parent over a sub-agent', () => {
    const base = inst('openclaw', `${HOME}/.openclaw`);
    const sub = inst('openclaw', `${HOME}/.openclaw`, { agentName: 'helper' });
    const dev = inst('openclaw', `${HOME}/.openclaw-dev`, { profile: 'dev' });
    const { byInstallation } = assignMcpServers([sub, base, dev], [
      config(`${HOME}/.openclaw-dev/openclaw.json`, ['openclaw'], ['dev-srv']),
      config(`${HOME}/.openclaw/openclaw.json`, ['openclaw'], ['base-srv']),
    ], { home: HOME, inventoried });
    expect(byInstallation.get(dev)!.map(s => s.name)).toEqual(['dev-srv']);
    expect(byInstallation.get(base)!.map(s => s.name)).toEqual(['base-srv']);
    expect(byInstallation.get(sub)).toEqual([]);
  });

  it("leaves other users' installations and agents VASO doesn't read MCP for without a list", () => {
    const other = inst('claude-code', '/home/other/.claude', { user: 'other' });
    const grok = inst('grok-bot', `${HOME}/.grokbot`);
    const { byInstallation } = assignMcpServers([other, grok], [
      config(`${HOME}/.claude.json`, ['claude-code'], ['mine']),
    ], { home: HOME, inventoried });
    expect(byInstallation.has(other)).toBe(false);
    expect(byInstallation.has(grok)).toBe(false);
  });

  it('gives servers to an installation relocated outside home (CODEX_HOME) whose config discovery found', () => {
    const codex = inst('codex', '/srv/codex');
    const { byInstallation } = assignMcpServers([codex], [
      config('/srv/codex/config.toml', ['codex'], ['relo']),
    ], { home: HOME, inventoried: new Set([...inventoried, 'codex']) });
    expect(byInstallation.get(codex)!.map(s => s.name)).toEqual(['relo']);
  });
});

describe('attachMcpInventories', () => {
  const dirs: string[] = [];
  afterEach(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
    dirs.length = 0;
  });

  it('reads the files under the provider home and attaches servers, keeping skill lists', async () => {
    const home = await mkdtemp(join(tmpdir(), 'vaso-mcpinv-'));
    dirs.push(home);
    await mkdir(join(home, '.cursor'));
    await writeFile(join(home, '.cursor', 'mcp.json'), JSON.stringify({ mcpServers: { gh: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github'], env: { GITHUB_TOKEN: 'ghp_' + 'x'.repeat(36) } } } }));
    const base = new LocalFSProvider();
    const fs = Object.assign(Object.create(base) as FSProvider, { homedir: () => home, getEnv: () => undefined, kind: 'snapshot' });
    const cursor = inst('cursor-cli', join(home, '.cursor'), { inventory: { skillsDirs: [], skills: [], otherEntries: [] } });

    const host = await attachMcpInventories([cursor], fs);

    expect(host).toEqual([]);
    expect(cursor.inventory?.mcpServers?.map(s => [s.name, s.package?.pin, s.envNames])).toEqual([['gh', 'none', ['GITHUB_TOKEN']]]);
    expect(JSON.stringify(cursor.inventory)).not.toContain('ghp_');
  });

  it('reads NanoClaw agent groups\' container.json and gives the servers to that checkout', async () => {
    const home = await mkdtemp(join(tmpdir(), 'vaso-mcpinv-nc-'));
    dirs.push(home);
    const checkout = join(home, 'nanoclaw');
    await mkdir(join(checkout, 'groups', 'main'), { recursive: true });
    await mkdir(join(checkout, 'groups', 'never-ran'), { recursive: true });
    await writeFile(join(checkout, 'groups', 'main', 'container.json'), JSON.stringify({
      mcpServers: {
        notes: { command: 'npx', args: ['-y', 'notes-mcp@1.2.0'], env: { NOTES_TOKEN: 'secret-value-123456789' } },
        crm: { type: 'http', url: 'https://crm.example.com/mcp', headers: { Authorization: 'Bearer zzzzzzzzzzzzzzzzzzzz' } },
      },
      packages: { apt: [], npm: [] },
      additionalMounts: [],
      skills: 'all',
    }));
    const base = new LocalFSProvider();
    const fs = Object.assign(Object.create(base) as FSProvider, { homedir: () => home, getEnv: () => undefined, kind: 'snapshot' });
    const nc = inst('nanoclaw', checkout);

    await attachMcpInventories([nc], fs);

    expect(nc.inventory?.mcpServers?.map(s => [s.name, s.transport, s.configFile.slice(checkout.length)])).toEqual([
      ['notes', 'stdio', '/groups/main/container.json'],
      ['crm', 'streamable-http', '/groups/main/container.json'],
    ]);
    expect(JSON.stringify(nc.inventory)).not.toContain('secret-value');
    expect(JSON.stringify(nc.inventory)).not.toContain('zzzzzzzz');
  });

  it('reads IronClaw Reborn MCP extensions from their manifest, header names only', async () => {
    const reborn = await mkdtemp(join(tmpdir(), 'vaso-mcpinv-ic-'));
    dirs.push(reborn);
    const ext = join(reborn, 'local-dev', 'system', 'extensions');
    await mkdir(join(ext, 'notion'), { recursive: true });
    await mkdir(join(ext, 'github'), { recursive: true });
    await writeFile(join(ext, 'notion', 'manifest.toml'), [
      'schema_version = "reborn.extension_manifest.v3"', 'id = "notion"', '',
      '[mcp]', 'server = "https://mcp.notion.com/mcp"', 'default_permission = "ask"', '',
      '[[mcp.credentials]]', 'handle = "mcp_notion_access_token"', 'injection = { type = "header", name = "authorization", prefix = "Bearer " }',
    ].join('\n'));
    // a WASM tool extension: no [mcp] section
    await writeFile(join(ext, 'github', 'manifest.toml'), 'schema_version = "reborn.extension_manifest.v3"\nid = "github"\n');
    const base = new LocalFSProvider();
    const fs = Object.assign(Object.create(base) as FSProvider, { homedir: () => reborn, getEnv: () => undefined, kind: 'snapshot' });
    const ic = inst('ironclaw', reborn);

    await attachMcpInventories([ic], fs);

    expect(ic.inventory?.mcpServers).toEqual([{
      name: 'notion',
      configFile: join(ext, 'notion', 'manifest.toml'),
      scope: 'extension',
      transport: 'streamable-http',
      url: 'https://mcp.notion.com/mcp',
      headerNames: ['authorization'],
    }]);
  });

  it('knows which agents it inventories', () => {
    const agents = inventoriedAgents(new LocalFSProvider());
    for (const a of ['claude-code', 'claude-desktop', 'codex', 'cursor-cli', 'devin', 'windsurf', 'openclaw', 'gemini-cli', 'hermes', 'zeroclaw', 'nanoclaw', 'ironclaw'] as AgentType[]) {
      expect(agents.has(a), a).toBe(true);
    }
    expect(agents.has('grok-bot')).toBe(false);
  });
});
