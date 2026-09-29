import { describe, it, expect } from 'vitest';
import { MCPDiscovery } from './discovery.js';
import type { FSProvider } from '../core/fs-provider.js';
import { join } from 'node:path';

const FIXTURES = join(__dirname, '../../testing/fixtures/mcp');

describe('MCPDiscovery', () => {
  it('discovers servers from insecure fixture config', async () => {
    const discovery = new MCPDiscovery();
    const result = await discovery.discoverFromPaths([
      join(FIXTURES, 'insecure/claude_desktop_config.json'),
    ]);

    console.log(`[MCPDiscovery] insecure → configs: ${result.configs.length}, servers: ${result.totalServers}`);

    expect(result.configs).toHaveLength(1);
    expect(result.totalServers).toBe(4);

    const servers = result.configs[0].servers;
    expect(servers.map(s => s.name)).toContain('risky-server');
    expect(servers.map(s => s.name)).toContain('insecure-sse');
    expect(servers.map(s => s.name)).toContain('admin-server');
    expect(servers.map(s => s.name)).toContain('typo-filesystam');
  });

  it('discovers servers from secure fixture config', async () => {
    const discovery = new MCPDiscovery();
    const result = await discovery.discoverFromPaths([
      join(FIXTURES, 'secure/claude_desktop_config.json'),
    ]);

    console.log(`[MCPDiscovery] secure → configs: ${result.configs.length}, servers: ${result.totalServers}`);

    expect(result.configs).toHaveLength(1);
    expect(result.totalServers).toBe(3);

    const servers = result.configs[0].servers;
    expect(servers.find(s => s.name === 'filesystem')?.transport).toBe('stdio');
    expect(servers.find(s => s.name === 'secure-sse')?.transport).toBe('sse');
  });

  it('parses transport types correctly', async () => {
    const discovery = new MCPDiscovery();
    const result = await discovery.discoverFromPaths([
      join(FIXTURES, 'insecure/claude_desktop_config.json'),
    ]);

    const servers = result.configs[0].servers;
    const sseServer = servers.find(s => s.name === 'insecure-sse');
    const stdioServer = servers.find(s => s.name === 'risky-server');

    console.log(`[MCPDiscovery] sse transport: ${sseServer?.transport}, stdio transport: ${stdioServer?.transport}`);

    expect(sseServer?.transport).toBe('sse');
    expect(stdioServer?.transport).toBe('stdio');
  });

  it('parses env blocks correctly', async () => {
    const discovery = new MCPDiscovery();
    const result = await discovery.discoverFromPaths([
      join(FIXTURES, 'insecure/claude_desktop_config.json'),
    ]);

    const risky = result.configs[0].servers.find(s => s.name === 'risky-server');

    console.log(`[MCPDiscovery] env keys: ${Object.keys(risky?.env ?? {}).join(', ')}`);

    expect(risky?.env).toBeDefined();
    expect(risky?.env?.OPENAI_API_KEY).toContain('sk-proj-');
    expect(risky?.env?.AWS_SECRET_ACCESS_KEY).toBeDefined();
    expect(risky?.env?.DATABASE_PASSWORD).toBeDefined();
  });

  it('returns empty result for non-existent paths', async () => {
    const discovery = new MCPDiscovery();
    const result = await discovery.discoverFromPaths([
      '/non/existent/path.json',
    ]);

    console.log(`[MCPDiscovery] non-existent → configs: ${result.configs.length}`);

    expect(result.configs).toHaveLength(0);
    expect(result.totalServers).toBe(0);
  });

  it('handles multiple config files', async () => {
    const discovery = new MCPDiscovery();
    const result = await discovery.discoverFromPaths([
      join(FIXTURES, 'insecure/claude_desktop_config.json'),
      join(FIXTURES, 'secure/claude_desktop_config.json'),
    ]);

    console.log(`[MCPDiscovery] multiple → configs: ${result.configs.length}, servers: ${result.totalServers}`);

    expect(result.configs).toHaveLength(2);
    expect(result.totalServers).toBe(7);
  });
});

describe('MCPDiscovery — Devin CLI locations', () => {
  it('discovers user and project Devin MCP configs (JSONC tolerated)', async () => {
    const files: Record<string, string> = {
      '/home/t/.config/devin/mcp_config.json':
        '{\n  // user-level\n  "mcpServers": { "gh": { "command": "npx", "args": ["-y", "@x/gh@1.0.0"] } }\n}',
      '/proj/.devin/mcp_config.local.json':
        '{ "mcpServers": { "remote": { "url": "http://mcp.example.test/mcp", "transport": "http" } } }',
    };
    const fs = {
      homedir: () => '/home/t',
      access: async (p: string) => p in files,
      readFile: async (p: string) => files[p],
      getEnv: () => undefined,
    } as unknown as FSProvider;
    const prevXdg = process.env.XDG_CONFIG_HOME;
    delete process.env.XDG_CONFIG_HOME;
    try {
      const result = await new MCPDiscovery(fs).discover('linux', '/proj');
      expect(result.configs.map(c => c.source)).toEqual(['Devin CLI', 'Devin CLI (local)']);
      expect(result.totalServers).toBe(2);
    } finally {
      if (prevXdg !== undefined) process.env.XDG_CONFIG_HOME = prevXdg;
    }
  });
});

describe('MCPDiscovery — Atomic Agent', () => {
  const config = JSON.stringify({
    version: 72,
    mcp: {
      servers: [
        { name: 'docs', enabled: true, trust: 'pure_read', env: { DOCS_TOKEN: 'x' },
          transport: { kind: 'stdio', command: 'npx', args: ['-y', '@x/docs'] } },
        { name: 'remote', enabled: true,
          transport: { kind: 'streamable_http', url: 'https://mcp.example.test/mcp', headers: { Authorization: 'Bearer t' } } },
        { name: 'legacy', enabled: true, transport: { kind: 'sse', url: 'http://10.0.0.5/sse' } },
        { name: 'off', enabled: false, transport: { kind: 'stdio', command: 'node' } },
      ],
    },
  });

  function makeFs(files: Record<string, string>, env: Record<string, string> = {}): FSProvider {
    return {
      homedir: () => '/home/t',
      access: async (p: string) => p in files,
      readFile: async (p: string) => files[p],
      getEnv: (k: string) => env[k],
    } as unknown as FSProvider;
  }

  it('parses mcp.servers[] from ~/.atomic-agent/config.json, skipping disabled servers', async () => {
    const result = await new MCPDiscovery(makeFs({ '/home/t/.atomic-agent/config.json': config })).discover('linux');
    expect(result.configs).toHaveLength(1);
    const [cfg] = result.configs;
    expect(cfg.source).toBe('Atomic Agent');
    expect(cfg.servers.map(s => [s.name, s.transport])).toEqual([
      ['docs', 'stdio'],
      ['remote', 'streamable-http'],
      ['legacy', 'sse'],
    ]);
    expect(cfg.servers[0]).toMatchObject({ command: 'npx', args: ['-y', '@x/docs'], env: { DOCS_TOKEN: 'x' } });
    expect(cfg.servers[1].headers).toEqual({ Authorization: 'Bearer t' });
  });

  it('honours ATOMIC_AGENT_STATE_DIR', async () => {
    const fs = makeFs({ '/srv/atomic/config.json': config }, { ATOMIC_AGENT_STATE_DIR: '/srv/atomic' });
    const result = await new MCPDiscovery(fs).discover('linux');
    expect(result.configs.map(c => c.filePath)).toEqual(['/srv/atomic/config.json']);
  });

  it('accepts the Atomic Agent dialect via --paths', async () => {
    const result = await new MCPDiscovery(makeFs({ '/tmp/c.json': config })).discoverFromPaths(['/tmp/c.json']);
    expect(result.totalServers).toBe(3);
  });

  it('ignores a config.json with no MCP servers', async () => {
    const empty = JSON.stringify({ version: 72, mcp: { servers: [] } });
    const result = await new MCPDiscovery(makeFs({ '/home/t/.atomic-agent/config.json': empty })).discover('linux');
    expect(result.configs).toEqual([]);
  });
});

describe('MCPDiscovery — agent frameworks', () => {
  function makeFs(files: Record<string, string>, env: Record<string, string> = {}): FSProvider {
    return {
      homedir: () => '/home/t',
      access: async (p: string) => p in files,
      readFile: async (p: string) => files[p],
      getEnv: (k: string) => env[k],
    } as unknown as FSProvider;
  }

  const nanobot = JSON.stringify({
    tools: { mcpServers: {
      fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
      remote: { type: 'streamableHttp', url: 'https://mcp.example.test/v1' },
    } },
  });
  const picoclaw = JSON.stringify({
    tools: { mcp: { servers: {
      gh: { enabled: true, command: 'npx', args: ['-y', '@x/github'], env: { GH_TOKEN: 't' } },
      events: { enabled: true, type: 'sse', url: 'http://10.0.0.5:9000/events' },
      off: { enabled: false, command: 'node' },
    } } },
  });
  const lyrie = JSON.stringify({ mcpServers: { memory: { command: 'bunx', args: ['mcp-memory'] } } });

  it('finds Nanobot tools.mcpServers, PicoClaw tools.mcp.servers and Lyrie ~/.lyrie/mcp.json', async () => {
    const result = await new MCPDiscovery(makeFs({
      '/home/t/.nanobot/config.json': nanobot,
      '/home/t/.picoclaw/config.json': picoclaw,
      '/home/t/.lyrie/mcp.json': lyrie,
    })).discover('linux');
    const bySource = Object.fromEntries(result.configs.map(c => [c.source, c.servers.map(s => [s.name, s.transport])]));
    expect(bySource).toEqual({
      Nanobot: [['fs', 'stdio'], ['remote', 'streamable-http']],
      PicoClaw: [['gh', 'stdio'], ['events', 'sse']],
      Lyrie: [['memory', 'stdio']],
    });
  });

  it('honours PICOCLAW_HOME and PICOCLAW_CONFIG', async () => {
    const home = await new MCPDiscovery(makeFs({ '/srv/pico/config.json': picoclaw }, { PICOCLAW_HOME: '/srv/pico' })).discover('linux');
    expect(home.configs.map(c => c.filePath)).toEqual(['/srv/pico/config.json']);
    const cfg = await new MCPDiscovery(makeFs({ '/etc/pc.json': picoclaw }, { PICOCLAW_CONFIG: '/etc/pc.json' })).discover('linux');
    expect(cfg.configs.map(c => c.filePath)).toEqual(['/etc/pc.json']);
  });

  it('accepts the framework dialects via --paths', async () => {
    const fs = makeFs({ '/a.json': nanobot, '/b.json': picoclaw });
    expect((await new MCPDiscovery(fs).discoverFromPaths(['/a.json', '/b.json'])).totalServers).toBe(4);
  });
});
