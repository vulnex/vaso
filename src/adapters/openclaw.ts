import { join, basename, dirname } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { deepMerge, getNestedValue } from '../core/utils.js';
import { discoverCliInstalls } from './cli-installs.js';
import { npmPackageJsonGlobs } from './nvm-binary.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';
import { includeRootsFromEnv, loadOpenclawConfig } from './openclaw-includes.js';
import { pathPresent } from './load-if-present.js';
import { containerEnvironment, isOpenclawAutoBind, openclawAutoBindHost, openclawEffectiveBind, OPENCLAW_CONTAINER_MARKERS } from './openclaw-bind.js';

/**
 * Files OpenClaw reads from its state dir besides the main config
 * (MAIN_CONFIG_NAMES / OPENCLAW_CONFIG_PATH): only the `.env` it loads into
 * its environment. config.yaml, config.json and gateway.yaml are no OpenClaw
 * config (src/config/paths.ts CONFIG_FILENAME = "openclaw.json", 2026.9.4 –
 * 2026.11.2); a leftover one there configures nothing, so it isn't scanned.
 */
const CONFIG_FILENAMES = [
  '.env',
];

const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/openclaw',
  '/opt/homebrew/bin/openclaw',
  '/usr/bin/openclaw',
];

const USER_CLI_RELATIVE_PATHS = [
  '.volta/bin/openclaw',
  '.local/bin/openclaw',
  '.nvm/current/bin/openclaw',
  '.npm-global/bin/openclaw',
  'bin/openclaw',
];

const AGENT_CONFIG_FILENAMES = [
  'agent.yaml', 'agent.json', 'config.yaml', 'config.json', '.env',
];

const APP_BUNDLE_PATH = '/Applications/OpenClaw.app';

const EXCLUDED_USERS = new Set(['Shared', 'Guest', '.localized']);

/**
 * The warning to show when `--all-users` can't do what it says: without root
 * (locally, or for the remote probe), other users' homes are unreadable and
 * only the scanning user's home is covered — which a report doesn't show.
 */
export function allUsersCoverageWarning(fs?: FSProvider): string | undefined {
  const _fs = fs ?? new LocalFSProvider();
  const privileged = _fs.isPrivileged ? _fs.isPrivileged() : process.getuid?.() === 0;
  if (privileged) return undefined;
  return `--all-users needs root to read other users' homes; only ${_fs.homedir()} was covered (run as root, or add --sudo for remote hosts)`;
}

/**
 * Get home directories to scan.
 * If allUsers is true and running as root, enumerate all user home dirs.
 * Otherwise return only the current user's home dir.
 */
export async function getUserHomeDirs(allUsers?: boolean, fs?: FSProvider): Promise<Array<{ home: string; user: string }>> {
  const _fs = fs ?? new LocalFSProvider();
  // Privilege of the scanned host: the local process, or the remote probe
  // (a --sudo snapshot scanned from an unprivileged workstation).
  const privileged = _fs.isPrivileged ? _fs.isPrivileged() : process.getuid?.() === 0;
  if (allUsers && privileged) {
    const baseDir = _fs.platform === 'darwin' ? '/Users' : '/home';
    try {
      const entries = await _fs.readdirEntries(baseDir);
      const dirs: Array<{ home: string; user: string }> = [];
      for (const entry of entries) {
        if (!entry.isDirectory) continue;
        if (EXCLUDED_USERS.has(entry.name)) continue;
        dirs.push({ home: join(baseDir, entry.name), user: entry.name });
      }
      // Also include /root on Linux
      if (_fs.platform === 'linux' && await _fs.access('/root')) {
        dirs.push({ home: '/root', user: 'root' });
      }
      return dirs;
    } catch {
      // Fallback to current user
    }
  }

  const home = _fs.homedir();
  return [{ home, user: basename(home) }];
}

/** `--profile <name>` state dirs: `<home>/.openclaw-<name>` (profile names as
 *  OpenClaw validates them; `default` is `.openclaw` itself). */
const PROFILE_DIR = /^\.openclaw-([a-z0-9][a-z0-9_-]{0,63})$/i;
/** Config file names in a state dir, in OpenClaw's order (2026.9.4 still
 *  reads the pre-rename clawdbot.json when there is no openclaw.json). */
export const MAIN_CONFIG_NAMES = ['openclaw.json', 'clawdbot.json'];
/** Pre-rename state dirs. OpenClaw reads ~/.clawdbot only while ~/.openclaw has
 *  no config; ~/.moltbot never. */
export const LEGACY_STATE_DIRS = ['.clawdbot', '.moltbot'];

/** `~` / `~/…` against `home`, as OpenClaw's resolveHomeRelativePath does. */
function expandTilde(value: string, home: string): string {
  return value === '~' || value.startsWith('~/') ? join(home, value.slice(1)) : value;
}

export interface OpenclawEnvPaths {
  /** OPENCLAW_HOME (its `~` is the OS home) or the user's home. */
  home: string;
  /** OPENCLAW_STATE_DIR — `~` is the effective home (OPENCLAW_HOME). */
  stateDir?: string;
  /** OPENCLAW_CONFIG_PATH — `~` is the effective home. */
  configPath?: string;
}

/**
 * The relocation variables as OpenClaw resolves them (verified with
 * `openclaw config file` 2026.9.4). They are the scanning user's (the
 * snapshot's on remote scans), so they apply to that user's home only.
 */
export function openclawEnvPaths(home: string, fs: FSProvider): OpenclawEnvPaths {
  const env = (name: string) => (home === fs.homedir() ? fs.getEnv(name)?.trim() || undefined : undefined);
  const openclawHome = env('OPENCLAW_HOME');
  const effective = openclawHome ? expandTilde(openclawHome, home) : home;
  const stateDir = env('OPENCLAW_STATE_DIR');
  const configPath = env('OPENCLAW_CONFIG_PATH');
  return {
    home: effective,
    stateDir: stateDir ? expandTilde(stateDir, effective) : undefined,
    configPath: configPath ? expandTilde(configPath, effective) : undefined,
  };
}

/** A state directory OpenClaw runs from, and the config file it loads there. */
export interface OpenclawLocation {
  dir: string;
  /** The config file (openclaw.json, clawdbot.json, or OPENCLAW_CONFIG_PATH). */
  mainConfig: string;
  profile?: string;
}

async function existingMainConfig(dir: string, fs: FSProvider): Promise<string | undefined> {
  for (const name of MAIN_CONFIG_NAMES) {
    if (await pathPresent(join(dir, name), fs)) return join(dir, name);
  }
  return undefined;
}

/**
 * Where OpenClaw runs from for a home directory:
 *   OPENCLAW_STATE_DIR set   that directory only (no fallback to ~/.openclaw)
 *   otherwise                the first existing of ~/.openclaw/{openclaw,clawdbot}.json,
 *                            ~/.clawdbot/{openclaw,clawdbot}.json; OPENCLAW_CONFIG_PATH
 *                            replaces the config file
 *   every ~/.openclaw-<name> a `--profile <name>` gateway, discovered without
 *                            the variable (a service unit sets it, the scan's shell doesn't)
 * Pre-rename dirs that aren't the live one are leftovers (OC-003), not
 * installations. No OpenClaw release (clawdbot 2026.1.4 – openclaw 2026.9.4)
 * reads /etc/openclaw: it appears only as an example location for files a
 * config names (secrets provider, TLS paths), so it is not an install.
 */
export async function openclawLocations(home: string, fs: FSProvider): Promise<OpenclawLocation[]> {
  const env = openclawEnvPaths(home, fs);
  const locations: OpenclawLocation[] = [];
  if (env.stateDir) {
    locations.push({
      dir: env.stateDir,
      mainConfig: env.configPath ?? (await existingMainConfig(env.stateDir, fs)) ?? join(env.stateDir, MAIN_CONFIG_NAMES[0]),
    });
  } else {
    const current = join(env.home, '.openclaw');
    const legacy = join(env.home, LEGACY_STATE_DIRS[0]);
    if (env.configPath) {
      // The state dir: ~/.openclaw when present, else an existing ~/.clawdbot
      const dir = !(await fs.access(current)) && await fs.access(legacy) ? legacy : current;
      locations.push({ dir, mainConfig: env.configPath });
    } else {
      const found = (await existingMainConfig(current, fs)) ?? (await existingMainConfig(legacy, fs));
      locations.push(found
        ? { dir: dirname(found), mainConfig: found }
        : { dir: current, mainConfig: join(current, MAIN_CONFIG_NAMES[0]) });
    }
  }

  try {
    const entries = await fs.readdirEntries(env.home);
    for (const entry of [...entries].sort((a, b) => a.name.localeCompare(b.name))) {
      const m = PROFILE_DIR.exec(entry.name);
      if (!m || !entry.isDirectory || m[1].toLowerCase() === 'default') continue;
      const dir = join(env.home, entry.name);
      if (locations.some(l => l.dir === dir)) continue;
      locations.push({ dir, profile: m[1], mainConfig: (await existingMainConfig(dir, fs)) ?? join(dir, MAIN_CONFIG_NAMES[0]) });
    }
  } catch {
    // home not listable
  }

  return locations;
}

/**
 * Find the first existing CLI binary path.
 */
/**
 * Check for macOS .app bundle.
 */
async function findAppBundle(fs: FSProvider): Promise<string | undefined> {
  if (fs.platform !== 'darwin') return undefined;
  if (await fs.access(APP_BUNDLE_PATH)) return APP_BUNDLE_PATH;
  return undefined;
}

/** The listen address an OpenClaw `gateway.bind` mode resolves to.
 *  `tailnet` depends on the host's interfaces, so it stays unknown; `auto`
 *  is 0.0.0.0 in a container, loopback outside (openclaw-bind.ts). */
function openclawBindHost(bind: unknown, customBindHost: unknown, inContainer: boolean | undefined): string | undefined {
  if (isOpenclawAutoBind(bind)) return openclawAutoBindHost(inContainer);
  switch (typeof bind === 'string' ? bind.toLowerCase() : undefined) {
    case 'loopback': return '127.0.0.1';
    case 'lan':
    case 'all': return '0.0.0.0';
    case 'custom': return typeof customBindHost === 'string' ? customBindHost : undefined;
    default: return undefined;
  }
}

/**
 * `mcp.servers` of every OpenClaw config the gateway loads for this home
 * (2026.9.4+ root schema: name → { command, args, env, cwd, url, transport,
 * headers, enabled, … }), read the way OpenClaw reads it (JSON5, `$include`).
 * `transport` is returned as `type`, the key the common server-map parser
 * reads; `vaso mcp` discovery parses the maps.
 */
export async function openclawMcpServerMaps(home: string, fs: FSProvider): Promise<Array<{ source: string; filePath: string; servers: Record<string, unknown> }>> {
  const out: Array<{ source: string; filePath: string; servers: Record<string, unknown> }> = [];
  const includeRoots = home === fs.homedir()
    ? includeRootsFromEnv(fs.getEnv('OPENCLAW_INCLUDE_ROOTS'), openclawEnvPaths(home, fs).home)
    : [];
  for (const { mainConfig, profile } of await openclawLocations(home, fs)) {
    let data: Record<string, unknown>;
    try {
      data = (await loadOpenclawConfig(mainConfig, fs, includeRoots)).data;
    } catch {
      continue;
    }
    const map = getNestedValue(data, 'mcp.servers');
    if (!map || typeof map !== 'object' || Array.isArray(map)) continue;
    const servers = Object.fromEntries(Object.entries(map as Record<string, unknown>).map(([name, raw]) => {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return [name, raw];
      const cfg = raw as Record<string, unknown>;
      return [name, typeof cfg.transport === 'string' && cfg.type === undefined ? { ...cfg, type: cfg.transport } : cfg];
    }));
    out.push({ source: profile ? `OpenClaw (profile ${profile})` : 'OpenClaw', filePath: mainConfig, servers });
  }
  return out;
}

/** The gateway listener a merged OpenClaw config describes on this host. */
function openclawGatewayInfo(config: Record<string, unknown>, inContainer: boolean | undefined): GatewayInfo | undefined {
  const gw = config.gateway;
  if (!gw || typeof gw !== 'object' || Array.isArray(gw)) return undefined;
  const g = gw as Record<string, unknown>;
  // gateway.mode "remote": this instance is a client of a gateway on another
  // host and runs no listener here (OpenClaw 2026.9.4 skips the local gateway)
  if (g.mode === 'remote') return undefined;
  // 2026.x schema: gateway.bind = auto | lan | loopback | custom | tailnet
  // (+ gateway.customBindHost) and gateway.tls = { enabled, … }; older
  // configs used gateway.host and a boolean tls. An unset bind is loopback,
  // or "auto" inside a container (openclawEffectiveBind).
  const tls = g.tls && typeof g.tls === 'object'
    ? (g.tls as Record<string, unknown>).enabled === true
    : typeof g.tls === 'boolean' ? g.tls : undefined;
  const auth = g.auth && typeof g.auth === 'object' ? (g.auth as Record<string, unknown>) : undefined;
  const host = typeof g.host === 'string' ? g.host
    : openclawBindHost(g.host === undefined ? openclawEffectiveBind(config, inContainer) : g.bind, g.customBindHost, inContainer);

  return {
    host,
    port: typeof g.port === 'number' ? g.port : undefined,
    authMode: typeof auth?.mode === 'string' ? auth.mode : undefined,
    tls,
  };
}

export const openclawAdapter: AgentAdapter = {
  agent: 'openclaw',
  displayName: 'OpenClaw',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const appBundle = await findAppBundle(fs);
    const inContainer = await containerEnvironment(fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const installs = await discoverCliInstalls(home, fs, {
        names: ['openclaw'],
        versionOptions: { correctionSuffix: true },
        systemPaths: SYSTEM_CLI_PATHS,
        userRelPaths: USER_CLI_RELATIVE_PATHS,
        version: async (bin, canExec) => (canExec ? queryCliVersion(bin, fs, { argSets: [['--version'], ['version']] }) : undefined)
          ?? (await readPackageVersion(bin, fs, 'openclaw')),
      });
      const cliBinary = installs.primary?.path;
      const locations = await openclawLocations(home, fs);
      let foundForUser = false;

      // OPENCLAW_INCLUDE_ROOTS: directories `$include` may reach besides the config's own
      const includeRoots = home === fs.homedir()
        ? includeRootsFromEnv(fs.getEnv('OPENCLAW_INCLUDE_ROOTS'), openclawEnvPaths(home, fs).home)
        : [];
      for (const { dir, mainConfig: mainConfigPath, profile } of locations) {
        if (!(await fs.access(dir)) && !(await fs.access(mainConfigPath))) continue;

        const configFiles = [];
        // The main config, then the .env beside it (the other main config
        // name is not read when one exists)
        const otherFiles = CONFIG_FILENAMES.map(f => join(dir, f));
        for (const filePath of [mainConfigPath, ...otherFiles]) {
          try {
            const config = filePath === mainConfigPath
              ? await loadOpenclawConfig(filePath, fs, includeRoots)
              : await loadConfig(filePath, fs);
            configFiles.push(config);
          } catch {
            // File doesn't exist or can't be parsed
          }
        }

        if (configFiles.length === 0) continue;

        // The installed CLI is what runs, so its version wins; openclaw.json's
        // top-level `version` / `meta.lastTouchedVersion` (the build that last
        // wrote the config) is the fallback for config-only installs.
        const mainConfig = configFiles.find(c => c.filePath === mainConfigPath);
        const meta = mainConfig?.data?.meta as Record<string, unknown> | undefined;
        const version = installs.primary?.version
          ?? (mainConfig?.data?.version as string)
          ?? (meta?.lastTouchedVersion as string)
          ?? (meta?.lastRunVersion as string);
        const skillsDir = this.getSkillsDir(dir);

        // The gateway, workspace and skill settings are the main config's;
        // the .env holds variables, not config keys
        const merged: Record<string, unknown> = { ...(mainConfig?.data ?? {}) };

        // Skill roots OpenClaw loads besides <dir>/skills: the workspace's
        // skills/ (agents.defaults.workspace, default <dir>/workspace) and
        // skills.load.extraDirs.
        const expand = (p: string) => (p === '~' || p.startsWith('~/') ? join(home, p.slice(1)) : p);
        const workspace = getNestedValue(merged, 'agents.defaults.workspace');
        const extraDirs = getNestedValue(merged, 'skills.load.extraDirs');
        const roots = [
          skillsDir,
          join(typeof workspace === 'string' && workspace.trim() ? expand(workspace.trim()) : join(dir, 'workspace'), 'skills'),
          ...(Array.isArray(extraDirs) ? extraDirs.filter((d): d is string => typeof d === 'string' && d.trim() !== '').map(d => expand(d.trim())) : []),
        ].filter((d): d is string => Boolean(d));
        const skillsDirs: string[] = [];
        for (const d of [...new Set(roots)]) if (d === skillsDir || await fs.access(d)) skillsDirs.push(d);

        const globalInstallation: AgentInstallation = {
          agent: 'openclaw',
          version,
          installDir: dir,
          configFiles,
          skillsDir,
          skillsDirs: skillsDirs.length > 1 ? skillsDirs : undefined,
          gateway: openclawGatewayInfo(merged, inContainer),
          models: await this.getModels?.(configFiles),
          profile,
          user: options?.allUsers ? user : undefined,
          appBundle,
          cliBinary,
          otherInstalls: installs.others.length > 0 ? installs.others : undefined,
        };
        installations.push(globalInstallation);

        // Discover per-agent subdirectories
        const agentsDir = join(dir, 'agents');
        if (await fs.access(agentsDir)) {
          try {
            const agentEntries = await fs.readdirEntries(agentsDir);
            for (const entry of agentEntries) {
              if (!entry.isDirectory) continue;
              const agentSubDir = join(agentsDir, entry.name);

              // Load agent-specific config files
              const agentConfigFiles = [];
              for (const filename of AGENT_CONFIG_FILENAMES) {
                const filePath = join(agentSubDir, filename);
                try {
                  const config = await loadConfig(filePath, fs);
                  agentConfigFiles.push(config);
                } catch {
                  // File doesn't exist or can't be parsed
                }
              }

              // 2026.x keeps per-agent runtime state in agents/<id>/ too
              // (agents/main/agent/auth-profiles.json, sessions/) — only a
              // directory with its own config file is a sub-agent install;
              // the rest are state dirs of agents configured in openclaw.json.
              if (agentConfigFiles.length === 0) continue;

              // Merge global config data with agent-specific data
              let agentMerged = { ...merged };
              for (const c of agentConfigFiles) {
                agentMerged = deepMerge(agentMerged, c.data) as Record<string, unknown>;
              }

              // Per-agent skills only: the shared dir is the parent
              // installation's, scanned (and reported) there once — analysing
              // it again per sub-agent only repeated the work, since
              // inherited findings are dropped from sub-agents anyway
              const agentSkillsDirs: string[] = [];
              const agentSkillsDir = join(agentSubDir, 'skills');
              if (await fs.access(agentSkillsDir)) {
                agentSkillsDirs.push(agentSkillsDir);
              }

              installations.push({
                agent: 'openclaw',
                agentName: entry.name,
                version,
                installDir: agentSubDir,
                configFiles: [...configFiles, ...agentConfigFiles],
                skillsDir: agentSkillsDirs.length > 0 ? agentSkillsDirs[agentSkillsDirs.length - 1] : undefined,
                skillsDirs: agentSkillsDirs.length > 0 ? agentSkillsDirs : undefined,
                gateway: openclawGatewayInfo(agentMerged, inContainer),
                models: await this.getModels?.([...configFiles, ...agentConfigFiles]),
                profile,
                user: options?.allUsers ? user : undefined,
                appBundle,
                cliBinary,
                otherInstalls: installs.others.length > 0 ? installs.others : undefined,
              });
            }
          } catch {
            // agents/ directory not readable
          }
        }

        foundForUser = true;
      }

      // If no configs found but CLI or .app exists, report a minimal installation
      if (!foundForUser && (cliBinary || appBundle)) {
        installations.push({
          agent: 'openclaw',
          installDir: locations[0].dir,
          version: installs.primary?.version,
          configFiles: [],
          cliBinary,
          otherInstalls: installs.others.length > 0 ? installs.others : undefined,
          appBundle,
          user: options?.allUsers ? user : undefined,
        });
      }
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const _fs = new LocalFSProvider();
    const env = openclawEnvPaths(_fs.homedir(), _fs);
    const dirs = [env.stateDir, join(env.home, '.openclaw'), join(env.home, LEGACY_STATE_DIRS[0])]
      .filter((d): d is string => Boolean(d));
    return [
      ...(env.configPath ? [env.configPath] : []),
      ...dirs.flatMap(dir => [...MAIN_CONFIG_NAMES, ...CONFIG_FILENAMES].map(f => join(dir, f))),
    ];
  },

  getSkillsDir(installDir: string): string | undefined {
    const candidates = [
      join(installDir, 'skills'),
      join(installDir, 'custom_skills'),
    ];
    return candidates[0];
  },

  /** The gateway a config describes; an `auto` bind stays unknown here
   *  (detect() resolves it against the scanned host). */
  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    return openclawGatewayInfo(config, undefined);
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    const main = configs.find(c => MAIN_CONFIG_NAMES.includes(basename(c.filePath)))
      ?? configs.find(c => c.format === 'json' && c.data?.models !== undefined);
    const providers = (main?.data?.models as Record<string, unknown> | undefined)
      ?.providers as Record<string, unknown> | undefined;
    if (!providers) return [];
    const out: ModelRef[] = [];
    for (const [provider, providerCfg] of Object.entries(providers)) {
      const list = (providerCfg as Record<string, unknown> | undefined)?.models;
      if (!Array.isArray(list)) continue;
      for (const m of list) {
        const id = (m?.id ?? m?.name) as string | undefined;
        if (id) out.push({ id, provider });
      }
    }
    return out;
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'memory.json'),
      join(installDir, 'conversations.db'),
    ];
  },

  /** Fixed-name credential files; OC-006 also walks credentials/, the
   *  per-agent auth stores and the state databases. */
  getCredentialPaths(installDir: string): string[] {
    return [
      join(installDir, '.env'),
      join(installDir, 'credentials.json'),
      join(installDir, 'auth.json'),
      join(installDir, 'credentials', 'oauth.json'),
      join(installDir, 'identity', 'device.json'),
    ];
  },

  getCLICommand(): string {
    return 'openclaw';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        // OPENCLAW_CONFIG_PATH names the config file (expanded by the probe);
        // OPENCLAW_HOME / OPENCLAW_STATE_DIR twins come from RELOCATABLE_TREES
        '${OPENCLAW_CONFIG_PATH}',
        '~/.openclaw/openclaw.json',
        '~/.openclaw/clawdbot.json',
        '~/.openclaw/.env',
        // ADV-002 reads the state dir's package.json (installed plugins)
        '~/.openclaw/package.json',
        '~/.clawdbot/openclaw.json',
        '~/.clawdbot/clawdbot.json',
        '~/.clawdbot/.env',
        '~/.moltbot/openclaw.json',
        '~/.moltbot/.env',
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        '~/.volta/bin/openclaw',
        '~/.local/bin/openclaw',
        '~/.nvm/current/bin/openclaw',
        '~/.npm-global/bin/openclaw',
        '~/bin/openclaw',
      ],
      // Credential stores, state databases and conversation memory —
      // permissions only (OC-006, POL-003), never content. A secrets file
      // provider at a configured path is local-only.
      metadataGlobPatterns: ['~/.openclaw', '~/.openclaw-*', '~/.clawdbot'].flatMap(d => [
        `${d}/credentials.json`,
        `${d}/auth.json`,
        `${d}/memory.json`,
        `${d}/conversations.db`,
        `${d}/identity/device.json`,
        `${d}/state/openclaw.sqlite*`,
        `${d}/credentials/**`,
        `${d}/agents/*/agent/openclaw-agent.sqlite*`,
        `${d}/agents/*/agent/{auth-profiles,auth-state,auth}.json`,
      // Container sentinels (gateway.bind "auto"): existence is the marker,
      // content never shipped
      ]).concat(OPENCLAW_CONTAINER_MARKERS.existenceOnly),
      globPatterns: [
        // package.json of every npm-global copy — versions non-primary copies on remote scans
        ...npmPackageJsonGlobs('openclaw'),
        '~/.openclaw/skills/**',
        '~/.openclaw/custom_skills/**',
        // default workspace's skills/ (a custom agents.defaults.workspace is local-only)
        '~/.openclaw/workspace/skills/**',
        // `$include` targets — any name inside the config directory; the
        // documented *.json5 ones are collected (others are reported as not
        // collected, never read from elsewhere)
        '~/.openclaw/**/*.json5',
        '~/.clawdbot/**/*.json5',
        // profile installs (OPENCLAW_PROFILE=<p> → ~/.openclaw-<p>)
        '~/.openclaw-*/openclaw.json',
        '~/.openclaw-*/clawdbot.json',
        '~/.openclaw-*/.env',
        '~/.openclaw-*/**/*.json5',
        '~/.openclaw-*/skills/**',
        '~/.openclaw/agents/*/agent.yaml',
        '~/.openclaw/agents/*/agent.json',
        '~/.openclaw/agents/*/config.yaml',
        '~/.openclaw/agents/*/config.json',
        '~/.openclaw/agents/*/.env',
        '~/.openclaw/agents/*/skills/**',
        // Legacy dirs load skills the same way
        ...['~/.clawdbot', '~/.moltbot'].flatMap(d => [`${d}/skills/**`, `${d}/agents/*/skills/**`]),
      ],
      commands: [
        { id: 'openclaw-which', cmd: 'which', args: ['openclaw'], timeout: 3000 },
        { id: 'openclaw-version', cmd: 'openclaw', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.openclaw',
        '~/.openclaw/agents',
        '~/.openclaw/skills',
        '~/.clawdbot',
        '~/.moltbot',
      ],
      envPrefixes: ['OPENCLAW_'],
      // FLY_MACHINE_ID / FLY_APP_NAME: OpenClaw's container markers (gateway.bind
      // "auto") — whether they are set, never their values
      envPresence: [...OPENCLAW_CONTAINER_MARKERS.envNames],
      systemPaths: [
        '/usr/local/bin/openclaw',
        '/opt/homebrew/bin/openclaw',
        '/usr/bin/openclaw',
        '/Applications/OpenClaw.app',
        // PID 1's cgroup list, recorded even when absent (openclaw-bind.ts)
        ...OPENCLAW_CONTAINER_MARKERS.content,
      ],
      systemDirListings: [],
    };
  },
};
