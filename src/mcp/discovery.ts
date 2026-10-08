import { join } from 'node:path';
import type { MCPConfig, MCPServerEntry, MCPDiscoveryResult } from './types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { stripJsonc } from '../core/jsonc.js';
import { parse as parseTOML } from 'smol-toml';
import type { Platform } from '../core/types.js';

interface ConfigLocation {
  source: string;
  path: string;
  /** Config dialect; defaults to the common `mcpServers` map. */
  shape?: 'atomic-agent' | 'nanobot' | 'picoclaw' | 'abacus' | 'abacus-config' | 'claude-json' | 'codex';
}

function getGlobalConfigLocations(platform: Platform, home: string): ConfigLocation[] {
  const locations: ConfigLocation[] = [];

  // Claude Desktop
  if (platform === 'darwin') {
    locations.push({
      source: 'Claude Desktop',
      path: join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'),
    });
  } else if (platform === 'linux') {
    locations.push({
      source: 'Claude Desktop',
      path: join(home, '.config', 'Claude', 'claude_desktop_config.json'),
    });
  } else if (platform === 'win32') {
    const appData = process.env.APPDATA ?? join(home, 'AppData', 'Roaming');
    locations.push({
      source: 'Claude Desktop',
      path: join(appData, 'Claude', 'claude_desktop_config.json'),
    });
  }

  // Claude Code: `claude mcp add` writes user-scope servers (and local-scope
  // ones, per project) to ~/.claude.json
  locations.push(
    { source: 'Claude Code', path: join(home, '.claude.json'), shape: 'claude-json' },
    { source: 'Claude Code', path: join(home, '.claude', 'mcp.json') },
  );

  // Gemini CLI / Qwen Code: `mcpServers` in settings.json (JSONC)
  locations.push(
    { source: 'Gemini CLI', path: join(home, '.gemini', 'settings.json') },
    { source: 'Qwen Code', path: join(home, '.qwen', 'settings.json') },
  );

  // Cursor
  locations.push({
    source: 'Cursor',
    path: join(home, '.cursor', 'mcp.json'),
  });

  // Windsurf
  locations.push({
    source: 'Windsurf',
    path: join(home, '.codeium', 'windsurf', 'mcp_config.json'),
  });

  // Abacus.AI CLI + desktop: mcp.json and the desktop's per-mode files are
  // server maps; config.json carries an array form.
  locations.push(
    { source: 'Abacus.AI', path: join(home, '.abacusai', 'mcp.json'), shape: 'abacus' },
    { source: 'Abacus.AI', path: join(home, '.abacusai', 'config.json'), shape: 'abacus-config' },
    { source: 'AbacusAI Desktop (code)', path: join(home, '.abacusai', 'desktop', 'mcp-code.json'), shape: 'abacus' },
    { source: 'AbacusAI Desktop (cowork)', path: join(home, '.abacusai', 'desktop', 'mcp-cowork.json'), shape: 'abacus' },
  );

  // Devin CLI (XDG config dir on POSIX, %APPDATA%\devin on Windows)
  const devinConfigDir = platform === 'win32'
    ? join(process.env.APPDATA ?? join(home, 'AppData', 'Roaming'), 'devin')
    : join(process.env.XDG_CONFIG_HOME?.trim() || join(home, '.config'), 'devin');
  locations.push({
    source: 'Devin CLI',
    path: join(devinConfigDir, 'mcp_config.json'),
  });

  return locations;
}

/** Codex: `[mcp_servers.<name>]` tables in `$CODEX_HOME/config.toml` (default ~/.codex). */
function getCodexLocation(home: string, fs: FSProvider): ConfigLocation {
  const codexHome = fs.getEnv('CODEX_HOME')?.trim() || join(home, '.codex');
  return { source: 'Codex', path: join(codexHome, 'config.toml'), shape: 'codex' };
}

/** Atomic Agent: `mcp.servers[]` in `<stateDir>/config.json`. */
function getAtomicAgentLocation(home: string, fs: FSProvider): ConfigLocation {
  const stateDir = fs.getEnv('ATOMIC_AGENT_STATE_DIR')?.trim() || join(home, '.atomic-agent');
  return { source: 'Atomic Agent', path: join(stateDir, 'config.json'), shape: 'atomic-agent' };
}

/** Agent frameworks that keep MCP servers in their own config files. */
function getFrameworkLocations(home: string, fs: FSProvider): ConfigLocation[] {
  const picoHome = fs.getEnv('PICOCLAW_HOME')?.trim() || join(home, '.picoclaw');
  return [
    // Nanobot (HKUDS): `tools.mcpServers` in ~/.nanobot/config.json
    { source: 'Nanobot', path: join(home, '.nanobot', 'config.json'), shape: 'nanobot' },
    // PicoClaw: `tools.mcp.servers` in $PICOCLAW_CONFIG or <home>/config.json
    { source: 'PicoClaw', path: fs.getEnv('PICOCLAW_CONFIG')?.trim() || join(picoHome, 'config.json'), shape: 'picoclaw' },
    // Lyrie: ~/.lyrie/mcp.json (`mcpServers`)
    { source: 'Lyrie', path: join(home, '.lyrie', 'mcp.json') },
  ];
}

function getProjectConfigLocations(projectDir: string): ConfigLocation[] {
  return [
    { source: 'Claude Code (project)', path: join(projectDir, '.mcp.json') },
    { source: 'Cursor (project)', path: join(projectDir, '.cursor', 'mcp.json') },
    { source: 'Windsurf (project)', path: join(projectDir, '.windsurf', 'mcp.json') },
    { source: 'Devin CLI (project)', path: join(projectDir, '.devin', 'mcp_config.json') },
    { source: 'Devin CLI (local)', path: join(projectDir, '.devin', 'mcp_config.local.json') },
    { source: 'Abacus.AI (project)', path: join(projectDir, '.abacusai', 'mcp.json'), shape: 'abacus' },
    { source: 'Abacus.AI (project)', path: join(projectDir, '.abacusai', 'config.json'), shape: 'abacus-config' },
    { source: 'VS Code', path: join(projectDir, '.vscode', 'mcp.json') },
    { source: 'Generic MCP', path: join(projectDir, 'mcp.json') },
  ];
}

/** Explicit transport names used by the supported config dialects. */
const TRANSPORT_TYPES: Record<string, MCPServerEntry['transport']> = {
  stdio: 'stdio',
  sse: 'sse',
  http: 'streamable-http',
  'streamable-http': 'streamable-http',
  streamableHttp: 'streamable-http',
};

/** A `name → { command, args, env, url, headers, type? }` server map.
 *  Servers explicitly disabled (`enabled: false`) are never connected. */
function parseServerMap(map: unknown): MCPServerEntry[] {
  const servers: MCPServerEntry[] = [];
  if (!map || typeof map !== 'object' || Array.isArray(map)) return servers;

  for (const [name, raw] of Object.entries(map as Record<string, unknown>)) {
    if (!raw || typeof raw !== 'object') continue;
    const config = raw as Record<string, unknown>;
    if (config.enabled === false) continue;

    let transport: MCPServerEntry['transport'] = TRANSPORT_TYPES[String(config.type)] ?? 'stdio';
    // Gemini CLI / Qwen Code: `httpUrl` is streamable HTTP, `url` is SSE
    const httpUrl = typeof config.httpUrl === 'string' ? config.httpUrl : undefined;
    if (!TRANSPORT_TYPES[String(config.type)] && httpUrl && !config.url) {
      transport = 'streamable-http';
    } else if (!TRANSPORT_TYPES[String(config.type)] && config.url) {
      const url = String(config.url);
      if (url.includes('/sse')) {
        transport = 'sse';
      } else {
        transport = 'streamable-http';
      }
    }

    servers.push({
      name,
      command: config.command ? String(config.command) : undefined,
      args: Array.isArray(config.args) ? config.args.map(String) : undefined,
      env: config.env && typeof config.env === 'object'
        ? Object.fromEntries(Object.entries(config.env as Record<string, unknown>).map(([k, v]) => [k, String(v)]))
        : undefined,
      headers: config.headers && typeof config.headers === 'object'
        ? Object.fromEntries(Object.entries(config.headers as Record<string, unknown>).map(([k, v]) => [k, String(v)]))
        : undefined,
      url: config.url ? String(config.url) : httpUrl,
      transport,
    });
  }

  return servers;
}

function parseServerEntries(data: Record<string, unknown>): MCPServerEntry[] {
  return parseServerMap(data.mcpServers);
}

function parseShape(shape: ConfigLocation['shape'], data: Record<string, unknown>): MCPServerEntry[] {
  const tools = data.tools as Record<string, unknown> | undefined;
  switch (shape) {
    case 'atomic-agent':
      return parseAtomicAgentEntries(data);
    case 'nanobot':
      return parseServerMap(tools?.mcpServers ?? tools?.mcp_servers);
    case 'abacus':
      return parseServerMap(withoutDisabled(data.mcpServers));
    case 'abacus-config':
      return parseServerMap(abacusArrayToMap(data.mcpServers));
    case 'codex':
      return parseServerMap(data.mcp_servers);
    case 'picoclaw': {
      // tools.mcp.enabled: false switches off the whole MCP integration
      const mcp = tools?.mcp as Record<string, unknown> | undefined;
      return mcp?.enabled === false ? [] : parseServerMap(mcp?.servers);
    }
    default:
      return parseServerEntries(data);
  }
}

/** Abacus.AI marks switched-off servers `disabled: true`; they are never launched. */
function withoutDisabled(map: unknown): unknown {
  if (!map || typeof map !== 'object' || Array.isArray(map)) return map;
  return Object.fromEntries(Object.entries(map as Record<string, unknown>).filter(
    ([, v]) => !(v && typeof v === 'object' && (v as Record<string, unknown>).disabled === true),
  ));
}

/** Abacus.AI config.json form: `mcpServers: [{ name, command, args, env }]`. */
function abacusArrayToMap(list: unknown): Record<string, unknown> {
  if (!Array.isArray(list)) return {};
  const map: Record<string, unknown> = {};
  for (const entry of list) {
    if (entry && typeof entry === 'object' && typeof (entry as Record<string, unknown>).name === 'string') {
      map[(entry as Record<string, unknown>).name as string] = entry;
    }
  }
  return map;
}

const ATOMIC_TRANSPORTS: Record<string, MCPServerEntry['transport']> = {
  stdio: 'stdio',
  streamable_http: 'streamable-http',
  sse: 'sse',
};

/** Atomic Agent's array form: `{ name, enabled, transport: { kind, command, args, url, headers }, env }`.
 *  Disabled servers are never connected, so they are skipped. */
function parseAtomicAgentEntries(data: Record<string, unknown>): MCPServerEntry[] {
  const mcp = data.mcp as Record<string, unknown> | undefined;
  if (!mcp || typeof mcp !== 'object' || !Array.isArray(mcp.servers)) return [];
  const stringMap = (v: unknown): Record<string, string> | undefined =>
    v && typeof v === 'object' && !Array.isArray(v)
      ? Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, val]) => [k, String(val)]))
      : undefined;

  const servers: MCPServerEntry[] = [];
  for (const raw of mcp.servers as unknown[]) {
    if (!raw || typeof raw !== 'object') continue;
    const entry = raw as Record<string, unknown>;
    if (entry.enabled === false || typeof entry.name !== 'string') continue;
    const t = entry.transport as Record<string, unknown> | undefined;
    const transport = ATOMIC_TRANSPORTS[String(t?.kind)];
    if (!t || !transport) continue;
    servers.push({
      name: entry.name,
      command: typeof t.command === 'string' ? t.command : undefined,
      args: Array.isArray(t.args) ? t.args.map(String) : undefined,
      env: stringMap(entry.env),
      headers: stringMap(t.headers),
      url: typeof t.url === 'string' ? t.url : undefined,
      transport,
    });
  }
  return servers;
}

/** Local-scope servers `claude mcp add` stores per project under `projects.<path>.mcpServers`. */
function claudeProjectConfigs(filePath: string, data: Record<string, unknown>): MCPConfig[] {
  const projects = data.projects;
  if (!projects || typeof projects !== 'object' || Array.isArray(projects)) return [];
  const configs: MCPConfig[] = [];
  for (const [projectPath, project] of Object.entries(projects as Record<string, unknown>)) {
    const servers = parseServerMap((project as Record<string, unknown> | null)?.mcpServers);
    if (servers.length > 0) configs.push({ source: `Claude Code (project ${projectPath})`, filePath, servers });
  }
  return configs;
}

export class MCPDiscovery {
  private fs: FSProvider;

  constructor(fs?: FSProvider) {
    this.fs = fs ?? new LocalFSProvider();
  }

  async discover(
    platform: Platform = process.platform,
    projectDir?: string,
  ): Promise<MCPDiscoveryResult> {
    const configs: MCPConfig[] = [];
    const home = this.fs.homedir();

    const locations = [
      ...getGlobalConfigLocations(platform, home),
      getCodexLocation(home, this.fs),
      getAtomicAgentLocation(home, this.fs),
      ...getFrameworkLocations(home, this.fs),
      ...(projectDir ? getProjectConfigLocations(projectDir) : []),
    ];

    for (const location of locations) {
      if (!await this.fs.access(location.path)) continue;

      try {
        const raw = await this.fs.readFile(location.path);
        const data = (location.shape === 'codex'
          ? parseTOML(raw.replace(/^\uFEFF/, ''))
          : JSON.parse(stripJsonc(raw))) as Record<string, unknown>;
        const servers = parseShape(location.shape, data);

        if (servers.length > 0) {
          configs.push({
            source: location.source,
            filePath: location.path,
            servers,
          });
        }
        if (location.shape === 'claude-json') configs.push(...claudeProjectConfigs(location.path, data));
      } catch {
        // Skip unparseable configs
      }
    }

    const totalServers = configs.reduce((sum, c) => sum + c.servers.length, 0);
    return { configs, totalServers };
  }

  async discoverFromPaths(paths: string[]): Promise<MCPDiscoveryResult> {
    const configs: MCPConfig[] = [];
    const unreadable: string[] = [];

    for (const filePath of paths) {
      if (!await this.fs.access(filePath)) { unreadable.push(filePath); continue; }

      try {
        const raw = await this.fs.readFile(filePath);
        const isToml = filePath.toLowerCase().endsWith('.toml');
        const data = (isToml ? parseTOML(raw.replace(/^\uFEFF/, '')) : JSON.parse(stripJsonc(raw))) as Record<string, unknown>;
        const tools = data.tools as Record<string, unknown> | undefined;
        const shape: ConfigLocation['shape'] = isToml ? 'codex'
          : data.mcpServers ? undefined
          : tools?.mcpServers || tools?.mcp_servers ? 'nanobot'
          : (tools?.mcp as Record<string, unknown> | undefined)?.servers ? 'picoclaw'
          : 'atomic-agent';
        const servers = parseShape(shape, data);

        if (servers.length > 0) {
          configs.push({
            source: 'Custom',
            filePath,
            servers,
          });
        }
        // ~/.claude.json: local-scope servers per project
        configs.push(...claudeProjectConfigs(filePath, data));
      } catch {
        // The caller named this file — report it rather than scan nothing
        unreadable.push(filePath);
      }
    }

    const totalServers = configs.reduce((sum, c) => sum + c.servers.length, 0);
    return { configs, totalServers, ...(unreadable.length > 0 ? { unreadable } : {}) };
  }
}
