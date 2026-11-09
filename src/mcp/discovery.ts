import { extname, join } from 'node:path';
import type { MCPConfig, MCPConfigLoadError, MCPServerEntry, MCPDiscoveryResult } from './types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { stripJsonc } from '../core/jsonc.js';
import { parse as parseTOML } from 'smol-toml';
import { claudeConfigPaths } from '../adapters/claude-code.js';
import { codexHome } from '../adapters/codex.js';
import { copilotHome } from '../adapters/copilot-cli.js';
import { geminiHome } from '../adapters/gemini.js';
import { qwenHome } from '../adapters/qwen-code.js';
import { xdgConfigDir as opencodeConfigDir } from '../adapters/opencode.js';
import { openclawMcpServerMaps } from '../adapters/openclaw.js';
import { parseYamlSafe } from '../core/yaml-safe.js';
import { pathPresent } from '../adapters/load-if-present.js';
import type { Platform } from '../core/types.js';

interface ConfigLocation {
  source: string;
  path: string;
  /** Config dialect; defaults to the common `mcpServers` map. */
  shape?: 'atomic-agent' | 'nanobot' | 'picoclaw' | 'abacus' | 'abacus-config' | 'claude-json' | 'codex' | 'opencode' | 'hermes' | 'vscode-settings';
  /** Value substituted for `${extensionPath}` (Gemini CLI extensions). */
  extensionPath?: string;
}

function getGlobalConfigLocations(platform: Platform, home: string, fs: FSProvider): ConfigLocation[] {
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
  // ($CLAUDE_CONFIG_DIR holds both when set)
  const claude = claudeConfigPaths(home, fs);
  locations.push(
    { source: 'Claude Code', path: claude.rootStateFile, shape: 'claude-json' },
    { source: 'Claude Code', path: join(claude.claudeDir, 'mcp.json') },
  );

  // Copilot CLI: user-level servers in <config dir>/mcp-config.json ($COPILOT_HOME)
  locations.push({ source: 'Copilot CLI', path: join(copilotHome(home, fs), 'mcp-config.json') });

  // Gemini CLI / Qwen Code: `mcpServers` in settings.json (JSONC)
  locations.push(
    { source: 'Gemini CLI', path: join(geminiHome(home, fs), 'settings.json') },
    { source: 'Qwen Code', path: join(qwenHome(home, fs), 'settings.json') },
  );

  // Cursor
  locations.push({
    source: 'Cursor',
    path: join(home, '.cursor', 'mcp.json'),
  });

  // VS Code user-level mcp.json (`servers` map) in the per-OS user-data dir
  const vscodeUser = platform === 'darwin'
    ? join(home, 'Library', 'Application Support', 'Code', 'User')
    : platform === 'win32'
      ? join(process.env.APPDATA ?? join(home, 'AppData', 'Roaming'), 'Code', 'User')
      : join(process.env.XDG_CONFIG_HOME?.trim() || join(home, '.config'), 'Code', 'User');
  locations.push(
    { source: 'VS Code', path: join(vscodeUser, 'mcp.json') },
    // Older form, still read: `"mcp": { "servers": {…} }` in user settings.json
    { source: 'VS Code (settings.json)', path: join(vscodeUser, 'settings.json'), shape: 'vscode-settings' },
  );

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
  // Devin before 3000.3 kept servers under `mcpServers` in config.json (newer
  // versions migrate them out on startup — docs.devin.ai/cli/extensibility/mcp).
  locations.push({ source: 'Devin CLI (config.json)', path: join(devinConfigDir, 'config.json') });

  // OpenCode: `mcp` in opencode.json[c] (opencode.ai/docs/mcp-servers), plus
  // the file $OPENCODE_CONFIG names.
  const opencodeDir = opencodeConfigDir(home, fs);
  locations.push(
    { source: 'OpenCode', path: join(opencodeDir, 'opencode.json'), shape: 'opencode' },
    { source: 'OpenCode', path: join(opencodeDir, 'opencode.jsonc'), shape: 'opencode' },
  );
  const opencodeExtra = home === fs.homedir() ? fs.getEnv('OPENCODE_CONFIG')?.trim() : undefined;
  if (opencodeExtra) locations.push({ source: 'OpenCode ($OPENCODE_CONFIG)', path: opencodeExtra, shape: 'opencode' });

  // Hermes: `mcp_servers` in $HERMES_HOME/config.yaml
  // (hermes-agent.nousresearch.com/docs/user-guide/features/mcp)
  const hermesHome = fs.getEnv('HERMES_HOME')?.trim() || join(home, '.hermes');
  locations.push({ source: 'Hermes', path: join(hermesHome, 'config.yaml'), shape: 'hermes' });

  return locations;
}

/** Codex: `[mcp_servers.<name>]` tables in `$CODEX_HOME/config.toml` (default ~/.codex). */
function getCodexLocation(home: string, fs: FSProvider): ConfigLocation {
  return { source: 'Codex', path: join(codexHome(home, fs), 'config.toml'), shape: 'codex' };
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

const GENERIC_MCP_SOURCE = 'Generic MCP';

function getProjectConfigLocations(projectDir: string): ConfigLocation[] {
  return [
    { source: 'Claude Code (project)', path: join(projectDir, '.mcp.json') },
    { source: 'Cursor (project)', path: join(projectDir, '.cursor', 'mcp.json') },
    { source: 'Windsurf (project)', path: join(projectDir, '.windsurf', 'mcp.json') },
    { source: 'Devin CLI (project)', path: join(projectDir, '.devin', 'mcp_config.json') },
    { source: 'Devin CLI (local)', path: join(projectDir, '.devin', 'mcp_config.local.json') },
    { source: 'Devin CLI (project config.json)', path: join(projectDir, '.devin', 'config.json') },
    { source: 'Devin CLI (project config.local.json)', path: join(projectDir, '.devin', 'config.local.json') },
    { source: 'Gemini CLI (project)', path: join(projectDir, '.gemini', 'settings.json') },
    { source: 'Qwen Code (project)', path: join(projectDir, '.qwen', 'settings.json') },
    // Copilot CLI reads a repo's .mcp.json (above) and .github/mcp.json
    { source: 'Copilot CLI (project)', path: join(projectDir, '.github', 'mcp.json') },
    { source: 'OpenCode (project)', path: join(projectDir, 'opencode.json'), shape: 'opencode' },
    { source: 'OpenCode (project)', path: join(projectDir, 'opencode.jsonc'), shape: 'opencode' },
    { source: 'Abacus.AI (project)', path: join(projectDir, '.abacusai', 'mcp.json'), shape: 'abacus' },
    { source: 'Abacus.AI (project)', path: join(projectDir, '.abacusai', 'config.json'), shape: 'abacus-config' },
    { source: 'VS Code', path: join(projectDir, '.vscode', 'mcp.json') },
    { source: 'VS Code (settings.json)', path: join(projectDir, '.vscode', 'settings.json'), shape: 'vscode-settings' },
    // Codex loads a trusted project's `.codex/config.toml` over the user config
    { source: 'Codex (project)', path: join(projectDir, '.codex', 'config.toml'), shape: 'codex' },
    { source: GENERIC_MCP_SOURCE, path: join(projectDir, 'mcp.json') },
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
 *  Servers explicitly disabled (`enabled: false`, Windsurf's `disabled: true`)
 *  are never connected. */
function parseServerMap(map: unknown): MCPServerEntry[] {
  const servers: MCPServerEntry[] = [];
  if (!map || typeof map !== 'object' || Array.isArray(map)) return servers;

  for (const [name, raw] of Object.entries(map as Record<string, unknown>)) {
    if (!raw || typeof raw !== 'object') continue;
    const config = raw as Record<string, unknown>;
    if (config.enabled === false || config.disabled === true) continue;
    // Windsurf / Devin Desktop name the remote URL `serverUrl`
    const url = typeof config.url === 'string' ? config.url
      : typeof config.serverUrl === 'string' ? config.serverUrl : undefined;

    let transport: MCPServerEntry['transport'] = TRANSPORT_TYPES[String(config.type)] ?? 'stdio';
    // Gemini CLI / Qwen Code: `httpUrl` is streamable HTTP, `url` is SSE
    const httpUrl = typeof config.httpUrl === 'string' ? config.httpUrl : undefined;
    if (!TRANSPORT_TYPES[String(config.type)] && httpUrl && !url) {
      transport = 'streamable-http';
    } else if (!TRANSPORT_TYPES[String(config.type)] && url) {
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
      url: url ?? httpUrl,
      transport,
    });
  }

  return servers;
}

function parseServerEntries(data: Record<string, unknown>): MCPServerEntry[] {
  // VS Code's mcp.json keys its servers `servers`
  return parseServerMap(data.mcpServers ?? data.servers);
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
      return parseServerMap(codexServers(data.mcp_servers));
    case 'opencode':
      return parseServerMap(opencodeServers(data.mcp));
    case 'hermes':
      return parseServerMap(data.mcp_servers);
    case 'vscode-settings': {
      const mcp = data.mcp as Record<string, unknown> | undefined;
      return mcp && typeof mcp === 'object' && !Array.isArray(mcp.servers) ? parseServerMap(mcp.servers) : [];
    }
    case 'picoclaw': {
      // tools.mcp.enabled: false switches off the whole MCP integration
      const mcp = tools?.mcp as Record<string, unknown> | undefined;
      return mcp?.enabled === false ? [] : parseServerMap(mcp?.servers);
    }
    default:
      return parseServerEntries(data);
  }
}

/**
 * Codex `[mcp_servers.<name>]` for streamable-HTTP servers carries its
 * credentials in `bearer_token_env_var` (the env var holding a bearer token),
 * `http_headers` (static) and `env_http_headers` (header → env var name)
 * (developers.openai.com/codex/mcp). Folded into `headers` so the auth checks
 * see them; env-sourced values are written as `${VAR}` references, which the
 * plaintext-secret checks skip.
 */
function codexServers(map: unknown): unknown {
  if (!map || typeof map !== 'object' || Array.isArray(map)) return map;
  return Object.fromEntries(Object.entries(map as Record<string, unknown>).map(([name, raw]) => {
    if (!raw || typeof raw !== 'object') return [name, raw];
    const cfg = raw as Record<string, unknown>;
    const headers: Record<string, string> = {};
    if (cfg.http_headers && typeof cfg.http_headers === 'object') {
      for (const [k, v] of Object.entries(cfg.http_headers as Record<string, unknown>)) headers[k] = String(v);
    }
    if (cfg.env_http_headers && typeof cfg.env_http_headers === 'object') {
      for (const [k, v] of Object.entries(cfg.env_http_headers as Record<string, unknown>)) headers[k] = `\${${String(v)}}`;
    }
    if (typeof cfg.bearer_token_env_var === 'string' && cfg.bearer_token_env_var.trim()) {
      headers.Authorization = `Bearer \${${cfg.bearer_token_env_var.trim()}}`;
    }
    return [name, Object.keys(headers).length > 0 ? { ...cfg, headers: { ...headers, ...(cfg.headers as object | undefined) } } : cfg];
  }));
}

/**
 * OpenCode `mcp.<name>`: `{ type: "local", command: [cmd, ...args],
 * environment }` or `{ type: "remote", url, headers }`, `enabled: false` to
 * switch one off (opencode.ai/docs/mcp-servers).
 */
function opencodeServers(map: unknown): unknown {
  if (!map || typeof map !== 'object' || Array.isArray(map)) return {};
  return Object.fromEntries(Object.entries(map as Record<string, unknown>).flatMap(([name, raw]) => {
    if (!raw || typeof raw !== 'object') return [];
    const cfg = raw as Record<string, unknown>;
    const command = Array.isArray(cfg.command) ? cfg.command.map(String) : typeof cfg.command === 'string' ? [cfg.command] : [];
    return [[name, {
      ...(command.length > 0 ? { command: command[0], args: command.slice(1) } : {}),
      env: cfg.environment,
      url: cfg.url,
      headers: cfg.headers,
      enabled: cfg.enabled,
      type: cfg.type === 'remote' ? 'http' : cfg.type === 'local' ? 'stdio' : undefined,
    }]];
  }));
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
      ...getGlobalConfigLocations(platform, home, this.fs),
      getCodexLocation(home, this.fs),
      getAtomicAgentLocation(home, this.fs),
      ...getFrameworkLocations(home, this.fs),
      ...await geminiExtensionLocations(home, this.fs),
      ...(projectDir ? getProjectConfigLocations(projectDir) : []),
    ];

    // One file, one config: run from $HOME, the project's `.cursor/mcp.json`
    // is the global `~/.cursor/mcp.json` (likewise `.gemini/settings.json`).
    const seen = new Set<string>();
    // Found but unreadable or unparseable: their servers go unscanned, so
    // the scan reports them (CONFIG-LOAD) instead of skipping them silently
    const loadErrors: MCPConfigLoadError[] = [];
    for (const location of locations) {
      if (!await pathPresent(location.path, this.fs)) continue;
      const real = await Promise.resolve(this.fs.realpath?.(location.path)).catch(() => undefined) ?? location.path;
      if (seen.has(real)) continue;
      seen.add(real);

      let raw: string;
      try {
        raw = await this.fs.readFile(location.path);
      } catch (err) {
        loadErrors.push({ source: location.source, filePath: location.path, stage: 'read', message: errorMessage(err) });
        continue;
      }
      try {
        const data = parseConfigText(raw, location.shape === 'codex' ? 'toml' : location.shape === 'hermes' ? 'yaml' : 'json');
        const servers = withExtensionPath(parseShape(location.shape, data), location.extensionPath);

        if (servers.length > 0) {
          configs.push({
            source: location.source,
            filePath: location.path,
            servers,
          });
        }
        if (location.shape === 'claude-json') configs.push(...claudeProjectConfigs(location.path, data));
      } catch (err) {
        // An empty file declares no servers: nothing goes unscanned. A bare
        // project mcp.json that doesn't parse may be some other tool's file.
        if (raw.trim() !== '' && location.source !== GENERIC_MCP_SOURCE) loadErrors.push({ source: location.source, filePath: location.path, stage: 'parse', message: errorMessage(err) });
      }
    }

    // OpenClaw: `mcp.servers` in the config its gateway loads (JSON5 with
    // `$include`, located like the adapter does)
    for (const oc of await openclawMcpServerMaps(home, this.fs).catch(() => [])) {
      const servers = parseServerMap(oc.servers);
      if (servers.length > 0) configs.push({ source: oc.source, filePath: oc.filePath, servers });
    }

    const totalServers = configs.reduce((sum, c) => sum + c.servers.length, 0);
    return { configs, totalServers, ...(loadErrors.length > 0 ? { loadErrors } : {}) };
  }

  async discoverFromPaths(paths: string[]): Promise<MCPDiscoveryResult> {
    const configs: MCPConfig[] = [];
    const unreadable: string[] = [];
    const empty: string[] = [];

    for (const filePath of paths) {
      if (!await this.fs.access(filePath)) { unreadable.push(filePath); continue; }

      try {
        const raw = await this.fs.readFile(filePath);
        const ext = extname(filePath).toLowerCase();
        const format = ext === '.toml' ? 'toml' : ext === '.yaml' || ext === '.yml' ? 'yaml' : 'json';
        const data = parseConfigText(raw, format);
        const shape = shapeOf(format, data);
        const servers = parseShape(shape, data);
        const projects = claudeProjectConfigs(filePath, data);

        if (servers.length > 0) {
          configs.push({
            source: 'Custom',
            filePath,
            servers,
          });
        }
        // ~/.claude.json: local-scope servers per project
        configs.push(...projects);
        if (servers.length === 0 && projects.length === 0) empty.push(filePath);
      } catch {
        // The caller named this file — report it rather than scan nothing
        unreadable.push(filePath);
      }
    }

    const totalServers = configs.reduce((sum, c) => sum + c.servers.length, 0);
    return {
      configs,
      totalServers,
      ...(unreadable.length > 0 ? { unreadable } : {}),
      ...(empty.length > 0 ? { empty } : {}),
    };
  }
}

/** Parse a config file's text: TOML (Codex), YAML (Hermes) or JSON/JSONC. */
function parseConfigText(raw: string, format: 'json' | 'toml' | 'yaml'): Record<string, unknown> {
  const text = raw.replace(/^\uFEFF/, '');
  const data = format === 'toml' ? parseTOML(text) : format === 'yaml' ? parseYamlSafe(text) : JSON.parse(stripJsonc(text));
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error('not a config object');
  return data as Record<string, unknown>;
}

/** The dialect of a config file given with -p, from its format and keys. */
function shapeOf(format: 'json' | 'toml' | 'yaml', data: Record<string, unknown>): ConfigLocation['shape'] {
  if (format === 'toml') return 'codex';
  const tools = data.tools as Record<string, unknown> | undefined;
  if (Array.isArray(data.mcpServers)) return 'abacus-config';
  if (data.mcpServers || data.servers) return undefined;
  if (data.mcp_servers) return 'hermes';
  if (tools?.mcpServers || tools?.mcp_servers) return 'nanobot';
  if ((tools?.mcp as Record<string, unknown> | undefined)?.servers) return 'picoclaw';
  const mcp = data.mcp as Record<string, unknown> | undefined;
  if (mcp && typeof mcp === 'object' && Array.isArray(mcp.servers)) return 'atomic-agent';
  if (mcp && typeof mcp === 'object' && mcp.servers && typeof mcp.servers === 'object') return 'vscode-settings';
  if (mcp && typeof mcp === 'object') return 'opencode';
  return 'atomic-agent';
}

/**
 * Gemini CLI extensions: each `<gemini home>/extensions/<name>/` carries a
 * `gemini-extension.json` whose `mcpServers` load like settings.json's, with
 * `${extensionPath}` naming the extension's directory
 * (geminicli.com/docs/extensions/reference).
 */
async function geminiExtensionLocations(home: string, fs: FSProvider): Promise<ConfigLocation[]> {
  const dir = join(geminiHome(home, fs), 'extensions');
  let names: string[];
  try {
    names = await fs.readdir(dir);
  } catch {
    return [];
  }
  return names.sort().map((name) => ({
    source: `Gemini CLI (extension ${name})`,
    path: join(dir, name, 'gemini-extension.json'),
    extensionPath: join(dir, name),
  }));
}

function withExtensionPath(servers: MCPServerEntry[], extensionPath: string | undefined): MCPServerEntry[] {
  if (!extensionPath) return servers;
  const sub = (v: string) => v.split('${extensionPath}').join(extensionPath);
  return servers.map((s) => ({
    ...s,
    ...(s.command ? { command: sub(s.command) } : {}),
    ...(s.args ? { args: s.args.map(sub) } : {}),
  }));
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
