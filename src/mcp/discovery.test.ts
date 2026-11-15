import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { MCPDiscovery } from './discovery.js';
import type { FSProvider } from '../core/fs-provider.js';
import { join } from 'node:path';
import { chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { LocalFSProvider } from '../core/local-fs-provider.js';

const FIXTURES = join(__dirname, '../../testing/fixtures/mcp');

describe('MCPDiscovery', () => {
  it('reports explicit paths that are missing or not valid JSON as unreadable', async () => {
    const discovery = new MCPDiscovery();
    const dir = await mkdtemp(join(tmpdir(), 'vaso-mcp-unreadable-'));
    try {
      const broken = join(dir, 'broken.json');
      const empty = join(dir, 'empty.json');
      await writeFile(broken, '{ "mcpServers": ');
      await writeFile(empty, '{}');
      const result = await discovery.discoverFromPaths([
        join(FIXTURES, 'secure/claude_desktop_config.json'), join(dir, 'missing.json'), broken, empty,
      ]);
      expect(result.totalServers).toBe(3);
      // A valid config with no servers is not an error
      expect(result.unreadable).toEqual([join(dir, 'missing.json'), broken]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('reads VS Code `servers`, Windsurf `serverUrl`, and skips disabled servers', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-mcp-dialects-'));
    try {
      const vscode = join(dir, 'vscode.json');
      const windsurf = join(dir, 'windsurf.json');
      await writeFile(vscode, JSON.stringify({ inputs: [], servers: { gh: { type: 'http', url: 'https://api.example.com/mcp' } } }));
      await writeFile(windsurf, JSON.stringify({ mcpServers: {
        remote: { serverUrl: 'http://10.0.0.5/mcp' },
        off: { command: 'npx', args: ['x'], disabled: true },
      } }));
      const result = await new MCPDiscovery().discoverFromPaths([vscode, windsurf]);
      const servers = result.configs.flatMap(c => c.servers);
      expect(servers.map(s => [s.name, s.url, s.transport])).toEqual([
        ['gh', 'https://api.example.com/mcp', 'streamable-http'],
        ['remote', 'http://10.0.0.5/mcp', 'streamable-http'],
      ]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('omits unreadable when every explicit path parsed', async () => {
    const result = await new MCPDiscovery().discoverFromPaths([join(FIXTURES, 'secure/claude_desktop_config.json')]);
    expect(result.unreadable).toBeUndefined();
  });

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

  it('skips PicoClaw servers when tools.mcp.enabled is false', async () => {
    const off = JSON.stringify({ tools: { mcp: { enabled: false, servers: { gh: { enabled: true, command: 'npx' } } } } });
    const result = await new MCPDiscovery(makeFs({ '/home/t/.picoclaw/config.json': off })).discover('linux');
    expect(result.configs).toEqual([]);
  });

  it('honours PICOCLAW_HOME and PICOCLAW_CONFIG', async () => {
    const home = await new MCPDiscovery(makeFs({ '/srv/pico/config.json': picoclaw }, { PICOCLAW_HOME: '/srv/pico' })).discover('linux');
    expect(home.configs.map(c => c.filePath)).toEqual(['/srv/pico/config.json']);
    const cfg = await new MCPDiscovery(makeFs({ '/etc/pc.json': picoclaw }, { PICOCLAW_CONFIG: '/etc/pc.json' })).discover('linux');
    expect(cfg.configs.map(c => c.filePath)).toEqual(['/etc/pc.json']);
  });

  it('finds ZeroClaw [[mcp.servers]] (array form only; [mcp] enabled = false turns them off)', async () => {
    const toml = [
      '[[mcp.servers]]', 'name = "gh"', 'transport = "stdio"', 'command = "npx"', 'args = ["-y", "@modelcontextprotocol/server-github"]', '',
      '[mcp.servers.env]', '',
      '[[mcp.servers]]', 'name = "remote"', 'transport = "http"', 'url = "https://mcp.example.test/mcp"', '',
      '[[mcp.servers]]', 'name = "events"', 'transport = "sse"', 'url = "https://mcp.example.test/sse"',
    ].join('\n');
    const result = await new MCPDiscovery(makeFs({ '/home/t/.zeroclaw/config.toml': toml })).discover('linux');
    expect(result.configs.map(c => [c.source, c.agents, c.servers.map(s => [s.name, s.transport])])).toEqual([
      ['ZeroClaw', ['zeroclaw'], [['gh', 'stdio'], ['remote', 'streamable-http'], ['events', 'sse']]],
    ]);

    const off = '[mcp]\nenabled = false\n\n[[mcp.servers]]\nname = "gh"\ncommand = "npx"\n';
    expect((await new MCPDiscovery(makeFs({ '/home/t/.zeroclaw/config.toml': off })).discover('linux')).configs).toEqual([]);
    // ZeroClaw resets a table-form [mcp.servers.<name>] section to defaults: nothing loads
    const table = '[mcp.servers.gh]\ntransport = "stdio"\ncommand = "npx"\n';
    expect((await new MCPDiscovery(makeFs({ '/home/t/.zeroclaw/config.toml': table })).discover('linux')).configs).toEqual([]);
  });

  it('reads ZeroClaw from ZEROCLAW_CONFIG_DIR', async () => {
    const toml = '[[mcp.servers]]\nname = "gh"\ncommand = "npx"\n';
    const result = await new MCPDiscovery(makeFs({ '/srv/zc/config.toml': toml }, { ZEROCLAW_CONFIG_DIR: '/srv/zc' })).discover('linux');
    expect(result.configs.map(c => c.filePath)).toEqual(['/srv/zc/config.toml']);
  });

  it('accepts the framework dialects via --paths', async () => {
    const fs = makeFs({ '/a.json': nanobot, '/b.json': picoclaw });
    expect((await new MCPDiscovery(fs).discoverFromPaths(['/a.json', '/b.json'])).totalServers).toBe(4);
  });
});

describe('MCPDiscovery — Abacus.AI', () => {
  it('reads mcp.json maps, the config.json array, desktop per-mode files and project configs, skipping disabled servers', async () => {
    const files: Record<string, string> = {
      '/home/t/.abacusai/mcp.json': JSON.stringify({ mcpServers: {
        gh: { command: 'npx', args: ['-y', '@x/gh@1.0.0'] },
        off: { command: 'npx', args: ['evil'], disabled: true },
      } }),
      '/home/t/.abacusai/config.json': JSON.stringify({ permissionMode: 'supervise', mcpServers: [{ name: 'db', command: 'uvx', args: ['mcp-server-sqlite'] }] }),
      '/home/t/.abacusai/desktop/mcp-cowork.json': JSON.stringify({ mcpServers: { remote: { type: 'http', url: 'https://mcp.example.test/mcp' } } }),
      '/proj/.abacusai/mcp.json': JSON.stringify({ mcpServers: { local: { command: 'node', args: ['srv.js'] } } }),
    };
    const fs = {
      homedir: () => '/home/t',
      access: async (p: string) => p in files,
      readFile: async (p: string) => files[p],
      getEnv: () => undefined,
    } as unknown as FSProvider;

    const result = await new MCPDiscovery(fs).discover('linux', '/proj');
    const abacus = result.configs.filter(c => c.source.startsWith('Abacus'));
    expect(abacus.map(c => [c.source, c.servers.map(s => s.name)])).toEqual([
      ['Abacus.AI', ['gh']],
      ['Abacus.AI', ['db']],
      ['AbacusAI Desktop (cowork)', ['remote']],
      ['Abacus.AI (project)', ['local']],
    ]);
    expect(abacus[2].servers[0].transport).toBe('streamable-http');
  });

  describe('agent config locations', () => {
    let home: string;
    class HomeFS extends LocalFSProvider { homedir() { return home; } getEnv() { return undefined; } }

    beforeAll(async () => {
      home = await mkdtemp(join(tmpdir(), 'vaso-mcp-home-'));
      const w = async (rel: string, body: string) => {
        await mkdir(join(home, rel, '..'), { recursive: true });
        await writeFile(join(home, rel), body);
      };
      await w('.claude.json', JSON.stringify({
        mcpServers: { user: { type: 'stdio', command: 'npx', args: ['-y', 'a-mcp'] } },
        projects: { '/repo': { mcpServers: { local: { type: 'http', url: 'https://x.example/mcp' } } }, '/empty': { mcpServers: {} } },
      }));
      await w('.gemini/settings.json', '{\n  // jsonc\n  "mcpServers": {"g": {"httpUrl": "http://g.example/mcp"}, "s": {"url": "http://g.example/sse"}},\n}');
      await w('.qwen/settings.json', JSON.stringify({ mcpServers: { q: { command: 'uvx', args: ['q-mcp'] } } }));
      await w('.codex/config.toml', '[mcp_servers.c]\ncommand = "npx"\nargs = ["-y", "c-mcp"]\n');
      await w('.cursor/mcp.json', '\uFEFF' + JSON.stringify({ mcpServers: { bom: { command: 'node', args: ['s.js'] } } }));
    });
    afterAll(() => rm(home, { recursive: true, force: true }));

    it('discovers Claude Code (user + per-project), Gemini, Qwen, Codex and BOM-prefixed configs', async () => {
      const result = await new MCPDiscovery(new HomeFS()).discover('linux');
      const bySource = Object.fromEntries(result.configs.map(c => [c.source, c.servers.map(s => `${s.name}:${s.transport}`)]));
      expect(bySource).toMatchObject({
        'Claude Code': ['user:stdio'],
        'Claude Code (project /repo)': ['local:streamable-http'],
        'Gemini CLI': ['g:streamable-http', 's:sse'],
        'Qwen Code': ['q:stdio'],
        Codex: ['c:stdio'],
        Cursor: ['bom:stdio'],
      });
      expect(bySource['Claude Code (project /empty)']).toBeUndefined();
      const gemini = result.configs.find(c => c.source === 'Gemini CLI')!;
      expect(gemini.servers[0].url).toBe('http://g.example/mcp');
    });

    it('parses an explicit config.toml / .claude.json path the same way', async () => {
      const result = await new MCPDiscovery(new HomeFS()).discoverFromPaths([join(home, '.codex/config.toml'), join(home, '.claude.json')]);
      expect(result.configs.map(c => c.source)).toEqual(['Custom', 'Custom', 'Claude Code (project /repo)']);
      expect(result.unreadable).toBeUndefined();
    });
  });

  describe('more agent configs (deep test 2026-10-15)', () => {
    let home: string;
    class HomeFS extends LocalFSProvider { homedir() { return home; } getEnv() { return undefined; } }
    const w = async (rel: string, body: string) => {
      await mkdir(join(home, rel, '..'), { recursive: true });
      await writeFile(join(home, rel), body);
    };

    beforeAll(async () => {
      home = await mkdtemp(join(tmpdir(), 'vaso-mcp-home2-'));
      await w('.config/opencode/opencode.json', JSON.stringify({ mcp: {
        loc: { type: 'local', command: ['npx', '-y', 'oc-mcp'], environment: { K: 'v' } },
        rem: { type: 'remote', url: 'https://oc.example/mcp', headers: { Authorization: 'Bearer x' } },
        off: { type: 'local', command: ['x'], enabled: false },
      } }));
      await w('.hermes/config.yaml', 'mcp_servers:\n  github:\n    command: npx\n    args: ["-y", "@modelcontextprotocol/server-github"]\n  stripe:\n    url: https://mcp.stripe.com\n');
      await w('.config/devin/config.json', '{ // legacy\n "mcpServers": { "old": { "command": "node", "args": ["o.js"] } } }');
      await w('.gemini/extensions/ext1/gemini-extension.json', JSON.stringify({ name: 'ext1', version: '1', mcpServers: { e: { command: 'node', args: ['${extensionPath}/srv.js'] } } }));
      await w('.codex/config.toml', '[mcp_servers.figma]\nurl = "http://mcp.corp.example.com/mcp"\nbearer_token_env_var = "FIGMA_TOKEN"\n[mcp_servers.hdr]\nurl = "https://mcp2.example.com/mcp"\nenv_http_headers = { "X-Api-Key" = "MY_KEY" }\n');
      await w('.cursor/mcp.json', JSON.stringify({ mcpServers: { cur: { command: 'node' } } }));
      await w('proj/.gemini/settings.json', JSON.stringify({ mcpServers: { pg: { command: 'node' } } }));
      await w('proj/.qwen/settings.json', JSON.stringify({ mcpServers: { pq: { command: 'node' } } }));
      await w('proj/opencode.jsonc', '{ "mcp": { "po": { "type": "local", "command": ["node", "p.js"] } } }');
      await w('repo/.git/HEAD', 'ref: refs/heads/main\n');
      await w('repo/.devin/config.json', JSON.stringify({ mcpServers: { rootsrv: { command: 'node' } } }));
      await w('repo/sub/.devin/mcp_config.json', JSON.stringify({ mcpServers: { subsrv: { command: 'node' } } }));
      await w('repo/sub/deep/x.txt', 'x');
    });

    it('finds Devin project servers from a subdirectory: the repo root and each .devin/ on the way', async () => {
      const result = await new MCPDiscovery(new HomeFS()).discover('linux', join(home, 'repo/sub/deep'));
      const devin = result.configs.filter(c => c.agents?.includes('devin') && c.scope === 'project');
      expect(devin.map(c => [c.servers.map(s => s.name).join(), c.projectRoot])).toEqual([
        ['rootsrv', join(home, 'repo')], ['subsrv', join(home, 'repo')],
      ]);
    });
    afterAll(() => rm(home, { recursive: true, force: true }));

    it('discovers OpenCode mcp, Hermes mcp_servers, legacy Devin config.json and Gemini extensions', async () => {
      const result = await new MCPDiscovery(new HomeFS()).discover('linux');
      const bySource = Object.fromEntries(result.configs.map(c => [c.source, c.servers]));
      expect(bySource.OpenCode.map(s => `${s.name}:${s.transport}`)).toEqual(['loc:stdio', 'rem:streamable-http']);
      expect(bySource.OpenCode[0]).toMatchObject({ command: 'npx', args: ['-y', 'oc-mcp'], env: { K: 'v' } });
      expect(bySource.Hermes.map(s => s.name)).toEqual(['github', 'stripe']);
      expect(bySource['Devin CLI (config.json)'].map(s => s.name)).toEqual(['old']);
      expect(bySource['Gemini CLI (extension ext1)'][0].args).toEqual([join(home, '.gemini/extensions/ext1') + '/srv.js']);
    });

    it('folds Codex bearer_token_env_var / env_http_headers into headers', async () => {
      const result = await new MCPDiscovery(new HomeFS()).discover('linux');
      const codex = result.configs.find(c => c.source === 'Codex')!;
      expect(codex.servers[0].headers).toEqual({ Authorization: 'Bearer ${FIGMA_TOKEN}' });
      expect(codex.servers[1].headers).toEqual({ 'X-Api-Key': '${MY_KEY}' });
    });

    it('reads Gemini/Qwen/OpenCode project configs and reports a file once when cwd is HOME', async () => {
      const proj = await new MCPDiscovery(new HomeFS()).discover('linux', join(home, 'proj'));
      const sources = proj.configs.map(c => c.source);
      expect(sources).toEqual(expect.arrayContaining(['Gemini CLI (project)', 'Qwen Code (project)', 'OpenCode (project)']));
      const atHome = await new MCPDiscovery(new HomeFS()).discover('linux', home);
      expect(atHome.configs.filter(c => c.filePath.endsWith(join('.cursor', 'mcp.json')))).toHaveLength(1);
    });

    it('follows QWEN_HOME and reads Copilot\'s .github/mcp.json', async () => {
      await w('qh/settings.json', JSON.stringify({ mcpServers: { relocated: { command: 'node' } } }));
      await w('proj/.github/mcp.json', JSON.stringify({ mcpServers: { gh: { command: 'npx', args: ['-y', 'gh-mcp'] } } }));
      class QwenHomeFS extends HomeFS { getEnv(k: string) { return k === 'QWEN_HOME' ? join(home, 'qh') : undefined; } }
      const result = await new MCPDiscovery(new QwenHomeFS()).discover('linux', join(home, 'proj'));
      const bySource = Object.fromEntries(result.configs.map(c => [c.source, c.servers.map(s => s.name)]));
      expect(bySource['Qwen Code']).toEqual(['relocated']);
      expect(bySource['Copilot CLI (project)']).toEqual(['gh']);
    });

    it('-p: reads the Abacus config.json array, YAML, and names files with no servers', async () => {
      await w('abacus.json', JSON.stringify({ mcpServers: [{ name: 'ab', command: 'node' }] }));
      await w('none.json', JSON.stringify({ theme: 'dark' }));
      const result = await new MCPDiscovery(new HomeFS()).discoverFromPaths([
        join(home, 'abacus.json'), join(home, '.hermes/config.yaml'), join(home, 'none.json'),
      ]);
      expect(result.configs.map(c => c.servers.map(s => s.name))).toEqual([['ab'], ['github', 'stripe']]);
      expect(result.empty).toEqual([join(home, 'none.json')]);
      expect(result.unreadable).toBeUndefined();
    });
  });
});

describe('MCPDiscovery — VS Code settings.json and Codex project config', () => {
  it('reads `mcp.servers` from VS Code settings.json and `[mcp_servers]` from a project .codex/config.toml', async () => {
    const files: Record<string, string> = {
      '/Users/t/Library/Application Support/Code/User/settings.json':
        '{\n  // user settings\n  "editor.tabSize": 2,\n  "mcp": { "servers": { "s_vscode_settings": { "command": "npx", "args": ["x"] } } }\n}',
      '/proj/.codex/config.toml': '[mcp_servers.s_codex_proj]\ncommand = "npx"\nargs = ["x"]\n',
      '/proj/.vscode/settings.json': '{ "editor.fontSize": 12 }',
    };
    const fs = {
      homedir: () => '/Users/t',
      access: async (p: string) => p in files,
      readFile: async (p: string) => files[p],
      getEnv: () => undefined,
    } as unknown as FSProvider;
    const result = await new MCPDiscovery(fs).discover('darwin', '/proj');
    const names = result.configs.flatMap(c => c.servers.map(s => `${c.source}:${s.name}`));
    expect(names).toContain('VS Code (settings.json):s_vscode_settings');
    expect(names).toContain('Codex (project):s_codex_proj');
    expect(result.totalServers).toBe(2);
  });

  it('recognizes the VS Code settings dialect via --paths', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'vaso-vss-'));
    try {
      const p = join(dir, 'settings.json');
      await writeFile(p, '{ "mcp": { "servers": { "a": { "command": "node", "args": ["s.js"] } } } }');
      const result = await new MCPDiscovery(new LocalFSProvider()).discoverFromPaths([p]);
      expect(result.configs[0]?.servers.map(s => s.name)).toEqual(['a']);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('MCPDiscovery — empty and unreadable configs (deep test 2026-11-09)', () => {
  let home: string;
  class HomeFS extends LocalFSProvider { homedir() { return home; } getEnv() { return undefined; } }
  const w = async (rel: string, body: string) => {
    await mkdir(join(home, rel, '..'), { recursive: true });
    await writeFile(join(home, rel), body);
  };
  beforeEach(async () => { home = await mkdtemp(join(tmpdir(), 'vaso-mcp-empty-')); });
  afterEach(async () => {
    await chmod(join(home, '.openclaw', 'openclaw.json'), 0o600).catch(() => undefined);
    await rm(home, { recursive: true, force: true });
  });

  it('treats comment-only JSONC and YAML configs as empty, not as load errors', async () => {
    await w('Library/Application Support/Code/User/settings.json', '// Place your settings in this file to overwrite the default settings\n');
    await w('Library/Application Support/Code/User/mcp.json', '/* nothing */\n');
    await w('proj/.vscode/settings.json', '// nothing yet\n');
    await w('.hermes/config.yaml', '# comment\n');
    const result = await new MCPDiscovery(new HomeFS()).discover('darwin', join(home, 'proj'));
    expect(result.loadErrors).toBeUndefined();
    expect(result.totalServers).toBe(0);
  });

  it('treats a YAML file of only `---` as empty; -p names comment-only files as empty', async () => {
    await w('.hermes/config.yaml', '---\n');
    expect((await new MCPDiscovery(new HomeFS()).discover('linux')).loadErrors).toBeUndefined();
    await w('c.json', '// nothing\n');
    const byPath = await new MCPDiscovery(new HomeFS()).discoverFromPaths([join(home, 'c.json'), join(home, '.hermes/config.yaml')]);
    expect(byPath.unreadable).toBeUndefined();
    expect(byPath.empty).toEqual([join(home, 'c.json'), join(home, '.hermes/config.yaml')]);
  });

  it('still reports a config that holds malformed content', async () => {
    await w('.hermes/config.yaml', 'mcp_servers: [unclosed\n');
    const result = await new MCPDiscovery(new HomeFS()).discover('linux');
    expect(result.loadErrors?.map(e => [e.source, e.stage])).toEqual([['Hermes', 'parse']]);
  });

  it('reports an unparsable or unreadable openclaw.json instead of finding no servers', async () => {
    await w('.openclaw/openclaw.json', '{ mcp: { servers: ');
    const bad = await new MCPDiscovery(new HomeFS()).discover('linux');
    expect(bad.loadErrors).toEqual([expect.objectContaining({ source: 'OpenClaw', filePath: join(home, '.openclaw/openclaw.json'), stage: 'parse' })]);

    await w('.openclaw/openclaw.json', '{ mcp: { servers: { a: { command: "npx", args: ["-y", "a-mcp"] } } } }');
    await chmod(join(home, '.openclaw/openclaw.json'), 0o000);
    const unreadable = await new MCPDiscovery(new HomeFS()).discover('linux');
    if (process.getuid?.() !== 0) {
      expect(unreadable.loadErrors).toEqual([expect.objectContaining({ source: 'OpenClaw', stage: 'read' })]);
    }
  });

  it('reports nothing when there is no openclaw.json', async () => {
    expect((await new MCPDiscovery(new HomeFS()).discover('linux')).loadErrors).toBeUndefined();
  });
});
