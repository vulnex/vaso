import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { loadConfigIfPresent } from './load-if-present.js';
import { getUserHomeDirs } from './openclaw.js';
import { discoverCliInstalls } from './cli-installs.js';
import { queryCliVersion } from './version-query.js';
import { applyEnvOverrides, type EnvOverrideSpec } from './env-overrides.js';
import { isWildcardAddress, wildcardFamilyLabel } from '../core/listen-address.js';

/**
 * PicoClaw (sipeed/picoclaw, Go) layout — verified against v0.3.x source:
 *
 *   $PICOCLAW_HOME (default ~/.picoclaw)
 *   ├── config.json            schema v3 (`"version": 3` is the SCHEMA version,
 *   │                          never the app version); $PICOCLAW_CONFIG overrides
 *   │                          the path. Written 0600. Unknown keys are rejected.
 *   ├── .security.yml          secrets (model api_keys, channel tokens, web/search
 *   │                          keys, skill-registry tokens) next to config.json.
 *   │                          Values: plaintext, enc://… (AES-GCM) or file://…
 *   ├── launcher-config.json   web launcher (port 18800, public, allowed_cidrs,
 *   │                          dashboard_password_hash) next to config.json
 *   ├── auth.json              OAuth credential store (`picoclaw auth login`)
 *   ├── skills/                global skills
 *   └── workspace/             agents.defaults.workspace — AGENT.md, SOUL.md,
 *       ├── skills/            workspace skills (onboard seeds these)
 *       ├── memory/ sessions/ state/ cron/
 *
 * Named agents (`agents.list[]`) without an explicit workspace use
 * `<defaults.workspace>/../workspace-<id>`. The version comes from
 * `picoclaw version` (`picoclaw --version` is an unknown flag, exit 1).
 */

const CLI_NAME = 'picoclaw';
const DEFAULT_GATEWAY_HOST = 'localhost';
const DEFAULT_GATEWAY_PORT = 18790;

/** Merged-config key under which detect() records the launcher's `public`
 *  flag for getGatewayInfo (launcher-config.json has no `gateway` section). */
const LAUNCHER_PUBLIC_KEY = '__picoclawLauncherPublic';
const GATEWAY_HOST_ENV_KEY = '__picoclawGatewayHostEnv';

export interface PicoclawPaths {
  /** $PICOCLAW_HOME or ~/.picoclaw — auth.json, global skills, default workspace. */
  home: string;
  /** $PICOCLAW_CONFIG or <home>/config.json. */
  configPath: string;
  /** Directory holding config.json, .security.yml and launcher-config.json. */
  configDir: string;
  /** Where the default workspace lives: `home`, except that workspace paths
   *  get `~` expanded and PICOCLAW_HOME itself doesn't. */
  workspaceRoot: string;
}

function envOverride(fs: FSProvider, key: string): string | undefined {
  const v = fs.getEnv(key)?.trim();
  return v ? v : undefined;
}

/**
 * Resolve PicoClaw's paths for a user home. The relocation env vars are read
 * from the scanned host (snapshot env on --host) and only apply to the user
 * the scan runs as — another user's process environment isn't observable.
 */
export function picoclawPaths(userHome: string, fs: FSProvider): PicoclawPaths {
  const ownHome = userHome === fs.homedir();
  const homeEnv = ownHome ? envOverride(fs, 'PICOCLAW_HOME') : undefined;
  // PicoClaw 0.3.1 takes PICOCLAW_HOME / PICOCLAW_CONFIG literally: `~/x` is
  // a directory named `~` under its working directory (`picoclaw status`:
  // "Config: ~/ph/config.json ✗"), while the default workspace derived from
  // the home is `~`-expanded like every workspace path.
  const home = homeEnv ? literalPath(homeEnv) : join(userHome, '.picoclaw');
  const configEnv = ownHome ? envOverride(fs, 'PICOCLAW_CONFIG') : undefined;
  const configPath = configEnv ? literalPath(configEnv) : join(home, 'config.json');
  const workspaceRoot = homeEnv ? expandHome(homeEnv, userHome) : home;
  return { home, configPath, configDir: dirname(configPath), workspaceRoot };
}

/**
 * Security-relevant fields PicoClaw's `env.Parse(cfg)` overrides from the
 * environment after loading config.json (caarlos0/env `env:"…"` struct tags in
 * pkg/config; booleans via strconv.ParseBool). PICOCLAW_GATEWAY_HOST is handled
 * by getGatewayInfo. Each name is also listed in the probe's envPrefixes.
 */
const ENV_OVERRIDES: EnvOverrideSpec[] = [
  { env: 'PICOCLAW_AGENTS_DEFAULTS_RESTRICT_TO_WORKSPACE', path: ['agents', 'defaults', 'restrict_to_workspace'], type: 'bool' },
  { env: 'PICOCLAW_AGENTS_DEFAULTS_ALLOW_READ_OUTSIDE_WORKSPACE', path: ['agents', 'defaults', 'allow_read_outside_workspace'], type: 'bool' },
  { env: 'PICOCLAW_TOOLS_EXEC_ENABLED', path: ['tools', 'exec', 'enabled'], type: 'bool' },
  { env: 'PICOCLAW_TOOLS_EXEC_ALLOW_REMOTE', path: ['tools', 'exec', 'allow_remote'], type: 'bool' },
  { env: 'PICOCLAW_TOOLS_EXEC_ENABLE_DENY_PATTERNS', path: ['tools', 'exec', 'enable_deny_patterns'], type: 'bool' },
  { env: 'PICOCLAW_GATEWAY_PORT', path: ['gateway', 'port'], type: 'int' },
];

function literalPath(p: string): string {
  return isAbsolute(p) ? p : resolve(p);
}

/** The config files workspaces are read from on remote scans ($PICOCLAW_HOME's is a relocated twin). */
const PICOCLAW_CONFIGS = ['${PICOCLAW_CONFIG}', '~/.picoclaw/config.json'];

function expandHome(p: string, userHome: string): string {
  if (p === '~') return userHome;
  if (p.startsWith('~/')) return join(userHome, p.slice(2));
  return isAbsolute(p) ? p : resolve(p);
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}

function nonEmptyString(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() ? v.trim() : undefined;
}

const NON_MAIN_CONFIGS = new Set(['auth.json', 'launcher-config.json', '.security.yml']);

/**
 * launcher-config.json with `public: true`: the web launcher starts the
 * gateway on every interface whatever config.json's gateway.host says, so
 * rewriting gateway.host changes nothing while it is set.
 */
export function picoclawPublicLauncher(configs: ParsedConfig[]): ParsedConfig | undefined {
  return configs.find(c => basename(c.filePath) === 'launcher-config.json' && asRecord(c.data)?.public === true);
}

/** The agent's config.json (possibly relocated/renamed via PICOCLAW_CONFIG). */
function isMainConfig(c: ParsedConfig): boolean {
  return c.format === 'json' && !NON_MAIN_CONFIGS.has(basename(c.filePath));
}

/** Upstream auth.canonicalProvider: `antigravity` is stored as `google-antigravity`. */
function canonicalAuthProvider(p: string | undefined): string | undefined {
  const n = p?.toLowerCase();
  return n === 'antigravity' ? 'google-antigravity' : n;
}

/** Mirror of upstream routing.NormalizeAgentID (lowercase, invalid → '-'). */
function normalizeAgentId(id: string): string {
  const lower = id.trim().toLowerCase();
  if (!lower) return 'main';
  return lower.replace(/[^a-z0-9_-]+/g, '-').replace(/^-+/, '').replace(/-+$/, '') || 'main';
}

/** Every workspace directory the config makes agents run in. */
export function picoclawWorkspaces(
  configData: Record<string, unknown> | undefined,
  picoHome: string,
  userHome: string,
): string[] {
  const agents = asRecord(configData?.agents);
  const defaults = asRecord(agents?.defaults);
  const defaultWs = nonEmptyString(defaults?.workspace);
  const primary = defaultWs ? expandHome(defaultWs, userHome) : join(picoHome, 'workspace');
  const out = [primary];
  const list = Array.isArray(agents?.list) ? agents!.list : [];
  for (const entry of list) {
    const a = asRecord(entry);
    if (!a) continue;
    const ws = nonEmptyString(a.workspace);
    if (ws) {
      out.push(expandHome(ws, userHome));
      continue;
    }
    const id = typeof a.id === 'string' ? normalizeAgentId(a.id) : 'main';
    if (a.default === true || id === 'main') continue;
    out.push(join(dirname(primary), `workspace-${id}`));
  }
  return [...new Set(out)];
}

/** Effective gateway bind: `*`/0.0.0.0/:: anywhere in the comma list → wildcard. */
function normalizeGatewayHost(raw: string): string {
  const tokens = raw.split(',').map(t => t.trim()).filter(Boolean);
  if (tokens.length === 0) return DEFAULT_GATEWAY_HOST;
  // The wildcard as configured (an IPv4 spelling first), so messages show
  // what the file says; `*` reads as 0.0.0.0
  const wild = tokens.filter(t => isWildcardAddress(t)).map(t => (t === '*' ? '0.0.0.0' : t));
  const v4 = wild.find(t => wildcardFamilyLabel(t) === '0.0.0.0');
  if (v4 !== undefined || wild.length > 0) return v4 ?? wild[0];
  return tokens.join(',');
}

export const picoclawAdapter: AgentAdapter = {
  agent: 'picoclaw',
  displayName: 'PicoClaw',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home: userHome, user } of userDirs) {
      const paths = picoclawPaths(userHome, fs);
      const candidates = [
        paths.configPath,
        join(paths.configDir, '.security.yml'),
        join(paths.home, 'auth.json'),
        join(paths.configDir, 'launcher-config.json'),
      ];

      const configFiles: ParsedConfig[] = [];
      for (const filePath of [...new Set(candidates)]) {
        try {
          { const loaded = await loadConfigIfPresent(filePath, fs); if (loaded) configFiles.push(loaded); }
        } catch {}
      }
      if (configFiles.length === 0) continue;

      const main = configFiles.find(c => c.filePath === paths.configPath && isMainConfig(c));
      // Env overrides describe the scanning user's process only (as above).
      if (main && userHome === fs.homedir()) main.data = applyEnvOverrides(main.data, ENV_OVERRIDES, fs);
      const launcher = configFiles.find(c => c.filePath.endsWith('launcher-config.json'));

      const workspaces = picoclawWorkspaces(main?.data, paths.workspaceRoot, userHome);
      const builtinSkills = userHome === fs.homedir() ? envOverride(fs, 'PICOCLAW_BUILTIN_SKILLS') : undefined;
      const skillsDirs = [
        ...workspaces.map(w => join(w, 'skills')),
        join(paths.home, 'skills'),
        ...(builtinSkills ? [expandHome(builtinSkills, userHome)] : []),
      ];

      const installs = await discoverCliInstalls(userHome, fs, {
        names: [CLI_NAME],
        version: (bin, canExec) => (canExec
          ? queryCliVersion(bin, fs, { argSets: [['version']], timeoutMs: 10000 })
          : undefined),
      });

      const gatewayInput: Record<string, unknown> = { ...(main?.data ?? {}) };
      if (asRecord(launcher?.data)?.public === true) gatewayInput[LAUNCHER_PUBLIC_KEY] = true;
      const hostEnv = userHome === fs.homedir() ? envOverride(fs, 'PICOCLAW_GATEWAY_HOST') : undefined;
      if (hostEnv) gatewayInput[GATEWAY_HOST_ENV_KEY] = hostEnv;

      installations.push({
        agent: 'picoclaw',
        installDir: paths.home,
        configFiles,
        skillsDir: skillsDirs[0],
        skillsDirs: [...new Set(skillsDirs)],
        gateway: main ? this.getGatewayInfo(gatewayInput) : undefined,
        models: await this.getModels?.(configFiles, fs),
        version: installs.primary?.version,
        user: options?.allUsers ? user : undefined,
        cliBinary: installs.primary?.path,
        otherInstalls: installs.others.length > 0 ? installs.others : undefined,
      });
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    const paths = picoclawPaths(fs.homedir(), fs);
    return [
      paths.configPath,
      join(paths.configDir, '.security.yml'),
      join(paths.home, 'auth.json'),
      join(paths.configDir, 'launcher-config.json'),
    ];
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'workspace', 'skills');
  },

  /**
   * PicoClaw's gateway has only host/port (no TLS or auth settings). The host
   * accepts a comma list and `*`; PICOCLAW_GATEWAY_HOST overrides it, and a
   * launcher with `public: true` starts the gateway on `*`.
   */
  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    const gw = asRecord(config.gateway) ?? {};
    const configured = nonEmptyString(config[GATEWAY_HOST_ENV_KEY])
      ?? nonEmptyString(gw.host)
      ?? DEFAULT_GATEWAY_HOST;
    const host = config[LAUNCHER_PUBLIC_KEY] === true ? '0.0.0.0' : normalizeGatewayHost(configured);
    const port = typeof gw.port === 'number' && gw.port > 0 ? gw.port : DEFAULT_GATEWAY_PORT;
    return { host, port };
  },

  /**
   * Models the agents actually use: the default (`agents.defaults.model_name`),
   * fallbacks / image model, per-agent `agents.list[].model`, plus any
   * `model_list[]` entry that carries credentials (config `api_keys` or a
   * `.security.yml` `model_list.<name>[:<n>].api_keys` entry) or OAuth. The
   * onboard template ships ~30 key-less catalogue entries; those are not
   * reported. Provider follows upstream ExtractProtocol: explicit `provider`
   * wins (model kept as-is), else the `provider/` prefix, else openai.
   */
  getModels(configs: ParsedConfig[]): ModelRef[] {
    const out: ModelRef[] = [];
    const seen = new Set<string>();
    const main = configs.find(isMainConfig);
    if (!main) return out;

    const list = (Array.isArray(main.data?.model_list) ? main.data.model_list : [])
      .map(asRecord)
      .filter((e): e is Record<string, unknown> => !!e && !!nonEmptyString(e.model_name));

    const security = configs.find(c => c.filePath.endsWith('.security.yml'));
    const securedNames = new Set<string>();
    const secModels = asRecord(security?.data?.model_list);
    for (const [key, value] of Object.entries(secModels ?? {})) {
      const keys = asRecord(value)?.api_keys;
      const single = asRecord(value)?.api_key;
      if ((Array.isArray(keys) && keys.some(k => nonEmptyString(k))) || nonEmptyString(single)) {
        securedNames.add(key.replace(/:\d+$/, ''));
      }
    }

    const agents = asRecord(main.data?.agents);
    const defaults = asRecord(agents?.defaults);
    const defaultName = nonEmptyString(defaults?.model_name);
    const referenced: string[] = [];
    const addRef = (v: unknown): void => {
      if (typeof v === 'string' && v.trim()) referenced.push(v.trim());
      else if (Array.isArray(v)) v.forEach(addRef);
      else {
        const m = asRecord(v);
        if (m) { addRef(m.primary); addRef(m.fallbacks); }
      }
    };
    addRef(defaults?.model_fallbacks);
    addRef(defaults?.image_model);
    addRef(defaults?.image_model_fallbacks);
    for (const entry of Array.isArray(agents?.list) ? agents!.list : []) {
      const a = asRecord(entry);
      addRef(a?.model);
      addRef(asRecord(a?.subagents)?.model);
    }

    const push = (e: Record<string, unknown>, isDefault: boolean): void => {
      const name = nonEmptyString(e.model_name)!;
      const model = nonEmptyString(e.model);
      if (!model) return;
      let provider = nonEmptyString(e.provider)?.toLowerCase();
      let id = model;
      if (!provider) {
        const slash = model.indexOf('/');
        provider = slash > 0 ? model.slice(0, slash).toLowerCase() : 'openai';
        id = slash > 0 ? model.slice(slash + 1) : model;
      }
      const via = isDefault ? undefined : name;
      const key = `${provider}|${id}|${via ?? ''}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push({ id, provider, ...(via ? { via } : {}) });
    };

    const auth = configs.find(c => basename(c.filePath) === 'auth.json');
    const oauthProviders = new Set(
      Object.values(asRecord(auth?.data?.credentials) ?? {})
        .map(c => canonicalAuthProvider(nonEmptyString(asRecord(c)?.provider)))
        .filter((p): p is string => !!p),
    );
    const hasCreds = (e: Record<string, unknown>): boolean => {
      const keys = e.api_keys;
      if (Array.isArray(keys) && keys.some(k => nonEmptyString(k))) return true;
      if (nonEmptyString(e.api_key)) return true;
      if (securedNames.has(nonEmptyString(e.model_name)!)) return true;
      const method = nonEmptyString(e.auth_method)?.toLowerCase();
      return (method === 'oauth' || method === 'token')
        && oauthProviders.has(canonicalAuthProvider(nonEmptyString(e.provider)) ?? '');
    };

    if (defaultName) for (const e of list) if (e.model_name === defaultName) push(e, true);
    for (const ref of referenced) for (const e of list) if (e.model_name === ref) push(e, false);
    for (const e of list) if (hasCreds(e)) push(e, e.model_name === defaultName);

    return out;
  },

  getMemoryFiles(installDir: string): string[] {
    const ws = join(installDir, 'workspace');
    return [
      join(ws, 'memory'),
      join(ws, 'sessions'),
      join(ws, 'state'),
    ];
  },

  /**
   * Secret-bearing files: `.security.yml` (API keys, channel tokens), the
   * OAuth store, launcher settings (dashboard password hash), config.json
   * (MCP server env/headers stay there; upstream writes it 0600) and the SSH
   * key PicoClaw derives the enc:// encryption key from.
   */
  getCredentialPaths(installDir: string, fs?: FSProvider): string[] {
    const provider = fs ?? new LocalFSProvider();
    const own = picoclawPaths(provider.homedir(), provider);
    // installDir is the resolved PicoClaw home. Env relocations only describe
    // the scanning user's installation; another user's lives at the defaults.
    const isOwn = own.home === installDir;
    const userHome = isOwn || basename(installDir) !== '.picoclaw' ? provider.homedir() : dirname(installDir);
    const configDir = isOwn ? own.configDir : installDir;
    const configPath = isOwn ? own.configPath : join(installDir, 'config.json');
    const sshKeyEnv = isOwn ? envOverride(provider, 'PICOCLAW_SSH_KEY_PATH') : undefined;
    return [...new Set([
      join(configDir, '.security.yml'),
      join(installDir, 'auth.json'),
      join(configDir, 'launcher-config.json'),
      configPath,
      sshKeyEnv ? expandHome(sshKeyEnv, userHome) : join(userHome, '.ssh', 'picoclaw_ed25519.key'),
    ])];
  },

  getCLICommand(): string {
    return CLI_NAME;
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        // $PICOCLAW_CONFIG names the config file itself (expanded by the probe)
        '${PICOCLAW_CONFIG}',
        // …and the files PicoClaw keeps next to it (launcherconfig.PathForAppConfig,
        // securityPath) — the same files, and treatment, as under ~/.picoclaw
        '${PICOCLAW_CONFIG}/../.security.yml',
        '${PICOCLAW_CONFIG}/../launcher-config.json',
        '~/.picoclaw/config.json',
        '~/.picoclaw/.security.yml',
        '~/.picoclaw/auth.json',
        '~/.picoclaw/launcher-config.json',
      ],
      globPatterns: [
        '~/.picoclaw/workspace/skills/**',
        '~/.picoclaw/workspace-*/skills/**',
        '~/.picoclaw/skills/**',
      ],
      // Conversation history, long-term memory, runtime state and cron
      // payloads are private — permissions only. The SSH key that derives the
      // enc:// credential key must never leave the host.
      metadataGlobPatterns: [
        '~/.picoclaw/workspace/sessions/**',
        '~/.picoclaw/workspace/memory/**',
        '~/.picoclaw/workspace/state/**',
        '~/.picoclaw/workspace/cron/**',
        '~/.ssh/picoclaw_ed25519.key',
      ],
      commands: [
        { id: 'picoclaw-which', cmd: 'which', args: [CLI_NAME], timeout: 3000 },
        { id: 'picoclaw-version', cmd: CLI_NAME, args: ['version'], timeout: 10000 },
      ],
      directoryListings: [
        '~/.picoclaw',
        '~/.picoclaw/workspace',
        '~/.picoclaw/workspace/skills',
        '~/.picoclaw/skills',
      ],
      // Only the relocation/bind knobs — never the PICOCLAW_ prefix, which
      // would ship PICOCLAW_KEY_PASSPHRASE (the enc:// passphrase).
      envPrefixes: [
        'PICOCLAW_HOME',
        'PICOCLAW_CONFIG',
        'PICOCLAW_BUILTIN_SKILLS',
        'PICOCLAW_GATEWAY_HOST',
        'PICOCLAW_SSH_KEY_PATH',
        ...ENV_OVERRIDES.map(o => o.env),
      ],
      systemPaths: [],
      systemDirListings: [],
      // Workspaces set in config.json (picoclawWorkspaces): the default one,
      // the `workspace-<id>` dirs named agents get beside it, and per-agent ones
      configRoots: [
        {
          configs: PICOCLAW_CONFIGS,
          format: 'json',
          kind: 'tree',
          keys: [['agents', 'defaults', 'workspace']],
          globs: ['skills/**', '../workspace-*/skills/**'],
        },
        {
          configs: PICOCLAW_CONFIGS,
          format: 'json',
          kind: 'tree',
          keys: [['agents', 'list', '*', 'workspace']],
          globs: ['skills/**'],
        },
      ],
    };
  },
};
