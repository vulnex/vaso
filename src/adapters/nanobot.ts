import { basename, dirname, isAbsolute, join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import { screenSkillRoots } from '../core/skill-root-scope.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { loadConfigIfPresent } from './load-if-present.js';
import { getUserHomeDirs } from './openclaw.js';
import { discoverCliInstalls } from './cli-installs.js';
import { queryCliVersion } from './version-query.js';
import { applyEnvDefaults } from './env-overrides.js';

/*
 * Nanobot (HKUDS/nanobot, PyPI `nanobot-ai`) — a Python agent framework.
 *
 * Layout (nanobot/config/{loader,paths}.py):
 *   ~/.nanobot/config.json         — the only settings file (camelCase JSON,
 *                                    secrets inline or as ${VAR} references)
 *   ~/.nanobot/pairing.json        — approved channel senders (DM pairing)
 *   ~/.nanobot/auth/{mcp,xai}.json — OAuth token stores (0600, dir 0700)
 *   ~/.nanobot/whatsapp-auth/      — native WhatsApp linked-device session
 *   ~/.nanobot/sessions/<ws-id>/   — chat history (*.jsonl)
 *   <workspace>/                   — agents.defaults.workspace, default
 *                                    ~/.nanobot/workspace: AGENTS.md, SOUL.md,
 *                                    USER.md, HEARTBEAT.md, memory/, skills/,
 *                                    plugins/, cron/jobs.json
 *
 * The data dir is the config file's parent; the only relocation is the
 * `--config` / `--workspace` CLI flags (there is no NANOBOT_HOME). `Config` is
 * a pydantic-settings model (env_prefix NANOBOT_, nested delimiter `__`), so
 * NANOBOT_* variables fill every setting config.json leaves unset, at any
 * depth; a value the file sets wins (verified with nanobot-ai 0.4.1's
 * load_config: NANOBOT_TOOLS__EXEC__ALLOW_PATTERNS='[".*"]' fills
 * tools.exec.allow_patterns under a file that sets tools.exec.enable).
 *
 * Nanobot is not an npm package — the npm `nanobot` name belongs to an
 * unrelated project, so no package.json version lookups.
 */

const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/nanobot',
  '/opt/homebrew/bin/nanobot',
  '/usr/bin/nanobot',
];

// `uv tool install nanobot-ai` and `pipx install nanobot-ai` both link the
// entry point into ~/.local/bin; `pip install --user` does too on Linux.
const USER_CLI_RELATIVE_PATHS = [
  '.local/bin/nanobot',
];

/** Isolated venvs the Python tool installers create for `nanobot-ai`. */
const USER_VENV_RELATIVE_PATHS = [
  '.local/share/uv/tools/nanobot-ai',
  '.local/share/pipx/venvs/nanobot-ai',
];

const DIST_INFO_RE = /^nanobot_ai-(\d+\.\d+\.\d+[0-9A-Za-z.+-]*)\.dist-info$/;

export const NANOBOT_DEFAULT_GATEWAY_PORT = 18790;
/** WebSocketConfig.port: the websocket channel (WebUI / client bridge). */
export const NANOBOT_DEFAULT_WEBSOCKET_PORT = 8765;

/**
 * The address the websocket channel listens on. Absent (or null) is the
 * WebSocketConfig default 127.0.0.1; a present empty string is kept by
 * pydantic and handed to asyncio's create_server, which binds every
 * interface (IPv4 and IPv6) for it. A whitespace-only host, or a bracketed
 * one (`[::]`, `[::1]` — getaddrinfo takes no brackets), fails to resolve,
 * so the channel never listens: undefined.
 */
export function nanobotWebsocketHost(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return '127.0.0.1';
  if (raw === '') return '0.0.0.0';
  if (raw.trim().startsWith('[')) return undefined;
  return raw.trim() === '' ? undefined : raw.trim();
}

/**
 * WebSocketConfig's `wildcard_host_requires_auth` validator: a host of
 * exactly "0.0.0.0" or "::" with no token, tokenIssueSecret or
 * trustedProxyAuth fails validation, so nanobot refuses to load config.json
 * and nothing listens (nanobot-ai 0.4.1).
 */
export function nanobotWebsocketRejected(ws: Record<string, unknown>): boolean {
  const field = (camel: string): unknown => camel in ws ? ws[camel] : ws[camel.replace(/[A-Z]/g, c => `_${c.toLowerCase()}`)];
  const host = field('host');
  if (host !== '0.0.0.0' && host !== '::') return false;
  const set = (v: unknown): boolean => typeof v === 'string' && v.trim().length > 0;
  const proxy = field('trustedProxyAuth');
  return !set(field('token')) && !set(field('tokenIssueSecret')) && (proxy === undefined || proxy === null);
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? v as Record<string, unknown> : undefined;
}

const NANOBOT_ENV = /^NANOBOT_(.+)$/i;

const toCamel = (snake: string): string => snake.replace(/_([a-z0-9])/g, (_m, c: string) => c.toUpperCase());
const toSnake = (camel: string): string => camel.replace(/[A-Z]/g, c => `_${c.toLowerCase()}`);

/**
 * config.json data with the NANOBOT_* environment filling what the file
 * leaves unset (see the header). pydantic-settings matches names
 * case-insensitively and JSON-decodes values of list/dict/model fields; a
 * scalar stays the string pydantic would coerce (the NB checks read bools
 * through `pyBool`). Variables set by env are recorded (`envOverridesOf`), so
 * NB-002 doesn't call an env-supplied secret a plaintext config value.
 */
export function applyNanobotEnv(data: Record<string, unknown>, fs: FSProvider): Record<string, unknown> {
  const entries: Array<{ env: string; path: string[]; value: unknown }> = [];
  for (const name of [...(fs.envNames?.() ?? [])].sort()) {
    const m = NANOBOT_ENV.exec(name);
    if (!m) continue;
    const raw = fs.getEnv(name);
    if (raw === undefined) continue;
    const parts = m[1].toLowerCase().split('__');
    if (parts.some(p => p === '')) continue;
    let value: unknown = raw;
    if (/^\s*[[{]/.test(raw)) {
      try { value = JSON.parse(raw); } catch { continue; } // nanobot refuses to load an undecodable value
    }
    entries.push({ env: name, path: parts.map(toCamel), value });
  }
  if (entries.length === 0) return data;
  return applyEnvDefaults(data, entries, (rec, key) =>
    key in rec ? key : toSnake(key) in rec ? toSnake(key) : undefined);
}

/** The user's home for an install: the parent of a default `~/.nanobot` data dir. */
function homeForInstall(installDir: string, fs: FSProvider): string {
  return basename(installDir) === '.nanobot' ? dirname(installDir) : fs.homedir();
}

/** Expand `~` and `${VAR}` the way nanobot does (Path.expanduser + env refs). */
function expandPath(raw: string, home: string, fs: FSProvider): string | undefined {
  let value = raw.trim();
  if (!value) return undefined;
  let unresolved = false;
  value = value.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}/g, (_m, name: string) => {
    const v = fs.getEnv(name);
    if (v === undefined) unresolved = true;
    return v ?? '';
  });
  if (unresolved) return undefined;
  if (value === '~') return home;
  if (value.startsWith('~/')) return join(home, value.slice(2));
  return isAbsolute(value) ? value : join(home, value);
}

/**
 * Resolve the agent workspace for a nanobot data dir: `agents.defaults.workspace`
 * from config.json, else NANOBOT_AGENTS__DEFAULTS__WORKSPACE (only honored by
 * nanobot when the key is absent), else `<home>/.nanobot/workspace`.
 */
export function nanobotWorkspaceDir(
  installDir: string,
  configData: Record<string, unknown> | undefined,
  fs: FSProvider,
): string {
  const home = homeForInstall(installDir, fs);
  const configured = asRecord(asRecord(asRecord(configData)?.agents)?.defaults)?.workspace;
  if (typeof configured === 'string') {
    const p = expandPath(configured, home, fs);
    if (p) return p;
  } else {
    const env = fs.getEnv('NANOBOT_AGENTS__DEFAULTS__WORKSPACE');
    if (env) {
      const p = expandPath(env, home, fs);
      if (p) return p;
    }
  }
  return join(home, '.nanobot', 'workspace');
}

async function listNames(dir: string, fs: FSProvider): Promise<string[]> {
  try {
    return await fs.readdir(dir);
  } catch {
    return [];
  }
}

/** Version from `<venv>/lib/python3.*\/site-packages/nanobot_ai-<ver>.dist-info`. */
async function venvDistVersion(venv: string, fs: FSProvider): Promise<string | undefined> {
  const libDir = join(venv, 'lib');
  for (const py of await listNames(libDir, fs)) {
    if (!py.startsWith('python')) continue;
    // site-packages (venvs, pip) or dist-packages (Debian system pip)
    for (const pkgDir of ['site-packages', 'dist-packages']) {
      for (const entry of await listNames(join(libDir, py, pkgDir), fs)) {
        const m = DIST_INFO_RE.exec(entry);
        if (m) return m[1];
      }
    }
  }
  return undefined;
}

/**
 * Package-metadata version of a nanobot entry point: the venv behind the
 * (resolved) binary, then the known uv / pipx venvs. File-only, so it works on
 * snapshots where `nanobot --version` can't be run for this copy.
 */
async function readDistVersion(bin: string, home: string, fs: FSProvider): Promise<string | undefined> {
  const venvs: string[] = [];
  try {
    venvs.push(dirname(dirname(await fs.realpath(bin))));
  } catch {}
  venvs.push(dirname(dirname(bin)));
  if (bin === join(home, '.local', 'bin', 'nanobot')) {
    venvs.push(...USER_VENV_RELATIVE_PATHS.map(p => join(home, p)));
  }
  for (const venv of [...new Set(venvs)]) {
    const v = await venvDistVersion(venv, fs);
    if (v) return v;
  }
  return undefined;
}

export const nanobotAdapter: AgentAdapter = {
  agent: 'nanobot',
  displayName: 'Nanobot',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const dataDir = join(home, '.nanobot');
      const configFiles: ParsedConfig[] = [];
      const configPath = join(dataDir, 'config.json');
      {
        const loaded = await loadConfigIfPresent(configPath, fs);
        // The environment describes the scanning user's process only.
        if (loaded && home === fs.homedir() && asRecord(loaded.data)) loaded.data = applyNanobotEnv(loaded.data, fs);
        if (loaded) configFiles.push(loaded);
      }

      const installs = await discoverCliInstalls(home, fs, {
        names: ['nanobot'],
        systemPaths: SYSTEM_CLI_PATHS,
        userRelPaths: USER_CLI_RELATIVE_PATHS,
        // A Python CLI: never in a Node version manager's globals.
        nvm: false,
        // `nanobot --version` prints "🐈 nanobot v0.3.5".
        version: async (bin, canExec) => (canExec ? queryCliVersion(bin, fs) : undefined)
          ?? (await readDistVersion(bin, home, fs)),
      });
      const cliBinary = installs.primary?.path;

      if (configFiles.length === 0 && !cliBinary) continue;
      // The CLI alone (never onboarded) is still an install worth versioning,
      // but only report it once — for the scanning user.
      if (configFiles.length === 0 && options?.allUsers && home !== fs.homedir()) continue;

      const configData = configFiles[0]?.data;
      const workspace = nanobotWorkspaceDir(dataDir, configData, fs);
      const roots = [join(workspace, 'skills')];
      if (await fs.access(join(workspace, 'plugins'))) roots.push(join(workspace, 'plugins'));
      // A workspace the config moves outside the home is not walked
      const { scan: skillsDirs, unscanned } = await screenSkillRoots(fs, roots, home);

      installations.push({
        agent: 'nanobot',
        installDir: dataDir,
        configFiles,
        skillsDir: skillsDirs[0],
        skillsDirs,
        ...(unscanned.length > 0 ? { unscannedSkillsDirs: unscanned } : {}),
        gateway: configFiles.length > 0 ? this.getGatewayInfo(configData ?? {}) : undefined,
        models: await this.getModels?.(configFiles, fs),
        user: options?.allUsers ? user : undefined,
        cliBinary,
        otherInstalls: installs.others.length > 0 ? installs.others : undefined,
        version: installs.primary?.version,
      });
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    return [join(home, '.nanobot', 'config.json')];
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'workspace', 'skills');
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    // The agent's network surface is the websocket channel (WebUI and client
    // bridge, always on: channels/websocket/manifest.py), default
    // 127.0.0.1:8765 (WebSocketConfig). `nanobot gateway`'s own
    // gateway.host:gateway.port (default 127.0.0.1:18790) serves only
    // GET /health (cli/gateway_runtime.py _health_server) — no agent access,
    // so it is not the gateway here (CFG-001 notes a wildcard one as info).
    const channels = asRecord(config.channels);
    const ws = asRecord(channels?.websocket) ?? {};
    const field = (camel: string): unknown => camel in ws ? ws[camel] : ws[camel.replace(/[A-Z]/g, c => `_${c.toLowerCase()}`)];
    const enabled = field('enabled');
    if (enabled === false || (typeof enabled === 'string' && /^(?:false|0|no|off)$/i.test(enabled.trim()))) return undefined;
    // A Unix socket replaces the TCP listener
    const unixSocket = field('unixSocketPath');
    if (typeof unixSocket === 'string' && unixSocket.trim()) return undefined;
    const host = field('host');
    const port = field('port');
    // wss:// when sslCertfile and sslKeyfile are both set (runtime.py
    // _build_ssl_context; one without the other fails the channel's start)
    const set = (v: unknown): boolean => typeof v === 'string' && v.trim().length > 0;
    const listenHost = nanobotWebsocketHost(host);
    if (listenHost === undefined || nanobotWebsocketRejected(ws)) return undefined;
    return {
      host: listenHost,
      // pydantic coerces a numeric string ("9000") to the int port
      port: typeof port === 'number' ? port : typeof port === 'string' && /^\s*\d{1,5}\s*$/.test(port) ? Number(port) : NANOBOT_DEFAULT_WEBSOCKET_PORT,
      tls: set(field('sslCertfile')) && set(field('sslKeyfile')),
    };
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    const main = configs.find(c => c.filePath.endsWith('config.json'));
    const data = main?.data;
    const defaults = asRecord(asRecord(data?.agents)?.defaults);
    const presets = asRecord(data?.modelPresets) ?? asRecord(data?.model_presets);
    const out: ModelRef[] = [];
    const seen = new Set<string>();

    // Models are "<provider>/<id>" (e.g. "anthropic/claude-opus-4-5") when the
    // provider is "auto"; an explicit provider routes the whole string to it.
    const push = (raw: unknown, forcedProvider: unknown, via?: string) => {
      if (typeof raw !== 'string' || !raw.trim()) return;
      const model = raw.trim();
      let provider: string | undefined;
      let id = model;
      if (typeof forcedProvider === 'string' && forcedProvider && forcedProvider !== 'auto') {
        provider = forcedProvider;
      } else {
        const slash = model.indexOf('/');
        if (slash !== -1) {
          provider = model.slice(0, slash);
          id = model.slice(slash + 1);
        }
      }
      const key = `${provider ?? ''}|${id}|${via ?? ''}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, ...(provider ? { provider } : {}), ...(via ? { via } : {}) });
    };

    // Active model: the selected preset, else the agents.defaults fields.
    const activePreset = typeof defaults?.modelPreset === 'string' ? defaults.modelPreset : undefined;
    const active = activePreset && activePreset !== 'default' ? asRecord(presets?.[activePreset]) : undefined;
    if (active) push(active.model, active.provider);
    else push(defaults?.model, defaults?.provider);

    for (const [name, preset] of Object.entries(presets ?? {})) {
      if (name === activePreset) continue;
      const p = asRecord(preset);
      if (p) push(p.model, p.provider, `preset:${name}`);
    }
    // Inline fallback models ({model, provider}); string entries name presets.
    if (Array.isArray(defaults?.fallbackModels)) {
      for (const fb of defaults.fallbackModels) {
        const f = asRecord(fb);
        if (f) push(f.model, f.provider, 'fallback');
      }
    }
    return out;
  },

  getMemoryFiles(installDir: string): string[] {
    const ws = join(installDir, 'workspace');
    return [
      join(ws, 'memory', 'MEMORY.md'),
      join(ws, 'memory', 'history.jsonl'),
      join(ws, 'SOUL.md'),
      join(ws, 'USER.md'),
      join(ws, 'AGENTS.md'),
      join(ws, 'HEARTBEAT.md'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    return [
      join(installDir, 'config.json'),
      join(installDir, 'pairing.json'),
      join(installDir, 'auth', 'mcp.json'),
      join(installDir, 'auth', 'xai.json'),
      join(installDir, 'whatsapp-auth', 'neonize.db'),
    ];
  },

  getCLICommand(): string {
    return 'nanobot';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.nanobot/config.json',
        // User-relative CLI install location — kept in sync with USER_CLI_RELATIVE_PATHS
        '~/.local/bin/nanobot',
      ],
      globPatterns: [
        // Skill / plugin code for the SKL analyzers.
        '~/.nanobot/workspace/skills/**',
        '~/.nanobot/workspace/plugins/**',
      ],
      // Credentials, chat history, memory and prompt files: the checks only
      // need existence + mode — content never leaves the host. The dist-info
      // entry carries the installed version in its directory name.
      metadataGlobPatterns: [
        '~/.nanobot/pairing.json',
        '~/.nanobot/auth/*',
        '~/.nanobot/whatsapp-auth/*',
        '~/.nanobot/sessions/*',
        '~/.nanobot/sessions/*/*',
        '~/.nanobot/history/*',
        '~/.nanobot/cron/*',
        '~/.nanobot/workspace/*.md',
        '~/.nanobot/workspace/memory/*',
        '~/.nanobot/workspace/cron/*',
        '~/.local/share/uv/tools/nanobot-ai/lib/python3*/site-packages/nanobot_ai-*.dist-info/METADATA',
        '~/.local/share/pipx/venvs/nanobot-ai/lib/python3*/site-packages/nanobot_ai-*.dist-info/METADATA',
      ],
      commands: [
        { id: 'nanobot-which', cmd: 'which', args: ['nanobot'], timeout: 3000 },
        { id: 'nanobot-version', cmd: 'nanobot', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.nanobot',
        '~/.nanobot/auth',
        '~/.nanobot/sessions',
        '~/.nanobot/workspace',
        '~/.nanobot/workspace/memory',
        '~/.nanobot/cron',
        '~/.nanobot/workspace/cron',
        '~/.nanobot/workspace/skills',
        '~/.nanobot/workspace/plugins',
      ],
      envPrefixes: ['NANOBOT_'],
      systemPaths: SYSTEM_CLI_PATHS,
      systemDirListings: [],
      // A workspace set in config.json (nanobotWorkspaceDir): its skills and
      // plugins, wherever it is
      configRoots: [{
        configs: ['~/.nanobot/config.json'],
        format: 'json',
        kind: 'tree',
        keys: [['agents', 'defaults', 'workspace']],
        globs: ['skills/**', 'plugins/**'],
        relative: 'home',
        expandEnv: true,
        envFallback: 'NANOBOT_AGENTS__DEFAULTS__WORKSPACE',
      }],
    };
  },

  // Privilege gradient: chat channels / WebUI / API callers → agent loop →
  // tools (shell exec, web fetch, MCP) → host filesystem and secrets.
  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'chat', label: 'Channels / WebUI / API', trustLevel: 0 },
        { id: 'core', label: 'Agent Loop', trustLevel: 1 },
        { id: 'exec', label: 'Tools (Shell, Web, MCP)', trustLevel: 2 },
        { id: 'host', label: 'Host FS + Secrets', trustLevel: 3 },
      ],
      components: [
        {
          id: 'edge',
          label: 'Chat Channels, WebSocket/WebUI, OpenAI-compatible API',
          zone: 'chat',
          guardCheckIds: ['NB-001', 'NB-008', 'NB-011'],
        },
        {
          id: 'bot',
          label: 'Agent Loop (prompt files, heartbeat, cron)',
          zone: 'core',
          guardCheckIds: ['NB-006', 'NB-007', 'NB-010'],
        },
        {
          id: 'shell',
          label: 'Shell Exec / Web Fetch / MCP Servers',
          zone: 'exec',
          guardCheckIds: ['NB-004', 'NB-005', 'NB-012'],
        },
        {
          id: 'fs',
          label: 'Host Filesystem, config.json Secrets, Session History',
          zone: 'host',
          guardCheckIds: ['NB-002', 'NB-003', 'NB-009'],
        },
      ],
      edges: [
        { from: 'edge', to: 'bot', kind: 'data', label: 'message' },
        { from: 'bot', to: 'shell', kind: 'control' },
        { from: 'shell', to: 'fs', kind: 'data' },
        {
          from: 'edge',
          to: 'fs',
          label: 'untrusted sender drives unconfined exec',
          triggerCheckIds: ['NB-001', 'NB-004', 'NB-008', 'NB-011'],
        },
      ],
    };
  },
};
