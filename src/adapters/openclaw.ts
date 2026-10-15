import { join, basename } from 'node:path';
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

const CONFIG_FILENAMES = [
  'openclaw.json',
  'config.yaml',
  'config.json',
  'gateway.yaml',
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

/**
 * OpenClaw config directories for a home directory, as OpenClaw resolves them
 * (verified with `openclaw config file` 2026.9.4):
 *   OPENCLAW_HOME=X       replaces the home directory: X/.openclaw[-<profile>]
 *   OPENCLAW_STATE_DIR=X  is the state directory itself: X/openclaw.json
 *   OPENCLAW_CONFIG_PATH  names the config file (see openclawConfigPathOverride)
 * The variables are the scanning user's (a snapshot's on remote scans), so
 * they apply to that user's home only.
 */
function getSearchDirs(home: string, profile?: string, fs?: FSProvider): string[] {
  const provider = fs ?? new LocalFSProvider();
  const ownHome = home === provider.homedir();
  const env = (name: string) => (ownHome ? provider.getEnv(name)?.trim() || undefined : undefined);
  const base = env('OPENCLAW_HOME') ?? home;
  const dirs = [
    join(base, '.openclaw'),
    join(base, '.clawdbot'),
    join(base, '.moltbot'),
  ];

  if (profile) {
    dirs.unshift(join(base, `.openclaw-${profile}`));
  }

  const stateDir = env('OPENCLAW_STATE_DIR');
  if (stateDir) dirs.unshift(stateDir);

  // System-wide config (only once, not per-user)
  if (ownHome) {
    dirs.push('/etc/openclaw');
  }

  return dirs;
}

/** OPENCLAW_CONFIG_PATH: the config file OpenClaw loads instead of <state dir>/openclaw.json. */
function openclawConfigPathOverride(home: string, fs: FSProvider): string | undefined {
  return home === fs.homedir() ? fs.getEnv('OPENCLAW_CONFIG_PATH')?.trim() || undefined : undefined;
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

/** The listen address an OpenClaw `gateway.bind` mode resolves to. `auto`
 *  and `tailnet` depend on the host's interfaces, so they stay unknown. */
function openclawBindHost(bind: unknown, customBindHost: unknown): string | undefined {
  switch (typeof bind === 'string' ? bind.toLowerCase() : undefined) {
    case 'loopback': return '127.0.0.1';
    case 'lan':
    case 'all': return '0.0.0.0';
    case 'custom': return typeof customBindHost === 'string' ? customBindHost : undefined;
    default: return undefined;
  }
}

export const openclawAdapter: AgentAdapter = {
  agent: 'openclaw',
  displayName: 'OpenClaw',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const profile = fs.getEnv('OPENCLAW_PROFILE') || undefined;
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const appBundle = await findAppBundle(fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const installs = await discoverCliInstalls(home, fs, {
        names: ['openclaw'],
        systemPaths: SYSTEM_CLI_PATHS,
        userRelPaths: USER_CLI_RELATIVE_PATHS,
        version: async (bin, canExec) => (canExec ? queryCliVersion(bin, fs, { argSets: [['--version'], ['version']] }) : undefined)
          ?? (await readPackageVersion(bin, fs, 'openclaw')),
      });
      const cliBinary = installs.primary?.path;
      const searchDirs = getSearchDirs(home, profile, fs);
      let foundForUser = false;

      const configPathOverride = openclawConfigPathOverride(home, fs);
      for (const [dirIndex, dir] of searchDirs.entries()) {
        // OPENCLAW_CONFIG_PATH replaces the primary (first) dir's openclaw.json
        const overrideHere = dirIndex === 0 ? configPathOverride : undefined;
        if (!(await fs.access(dir)) && !(overrideHere && await fs.access(overrideHere))) continue;

        const configFiles = [];
        for (const filename of CONFIG_FILENAMES) {
          const filePath = overrideHere && filename === 'openclaw.json' ? overrideHere : join(dir, filename);
          try {
            const config = await loadConfig(filePath, fs);
            configFiles.push(config);
          } catch {
            // File doesn't exist or can't be parsed
          }
        }

        if (configFiles.length === 0) continue;

        // The installed CLI is what runs, so its version wins; openclaw.json's
        // top-level `version` / `meta.lastTouchedVersion` (the build that last
        // wrote the config) is the fallback for config-only installs.
        const mainConfig = configFiles.find(c => c.filePath.endsWith('openclaw.json'));
        const meta = mainConfig?.data?.meta as Record<string, unknown> | undefined;
        const version = installs.primary?.version
          ?? (mainConfig?.data?.version as string)
          ?? (meta?.lastTouchedVersion as string)
          ?? (meta?.lastRunVersion as string);
        const skillsDir = this.getSkillsDir(dir);

        // Merge all config data to extract gateway info
        const merged: Record<string, unknown> = {};
        for (const c of configFiles) {
          Object.assign(merged, c.data);
        }

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
          gateway: this.getGatewayInfo(merged),
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

              // Build skillsDirs: shared + per-agent
              const agentSkillsDirs: string[] = [];
              if (skillsDir && await fs.access(skillsDir)) {
                agentSkillsDirs.push(skillsDir);
              }
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
                gateway: this.getGatewayInfo(agentMerged),
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
          installDir: join(home, '.openclaw'),
          version: installs.primary?.version,
          configFiles: [],
          cliBinary,
          otherInstalls: installs.others.length > 0 ? installs.others : undefined,
          appBundle,
          profile,
          user: options?.allUsers ? user : undefined,
        });
      }
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const _fs = new LocalFSProvider();
    const dirs = getSearchDirs(_fs.homedir(), _fs.getEnv('OPENCLAW_PROFILE') || undefined, _fs);
    return dirs.flatMap(dir =>
      CONFIG_FILENAMES.map(f => join(dir, f))
    );
  },

  getSkillsDir(installDir: string): string | undefined {
    const candidates = [
      join(installDir, 'skills'),
      join(installDir, 'custom_skills'),
    ];
    return candidates[0];
  },

  getGatewayInfo(config: Record<string, unknown>): GatewayInfo | undefined {
    const gw = config.gateway;
    if (!gw || typeof gw !== 'object' || Array.isArray(gw)) return undefined;
    const g = gw as Record<string, unknown>;
    // gateway.mode "remote": this instance is a client of a gateway on another
    // host and runs no listener here (OpenClaw 2026.9.4 skips the local gateway)
    if (g.mode === 'remote') return undefined;
    // 2026.x schema: gateway.bind = auto | lan | loopback | custom | tailnet
    // (+ gateway.customBindHost) and gateway.tls = { enabled, … }; older
    // configs used gateway.host and a boolean tls. An unset bind is loopback
    // (`gateway.bind ?? "loopback"` throughout 2026.9.4).
    const tls = g.tls && typeof g.tls === 'object'
      ? (g.tls as Record<string, unknown>).enabled === true
      : typeof g.tls === 'boolean' ? g.tls : undefined;
    const auth = g.auth && typeof g.auth === 'object' ? (g.auth as Record<string, unknown>) : undefined;
    const host = typeof g.host === 'string' ? g.host
      : g.bind === undefined && g.host === undefined ? '127.0.0.1'
      : openclawBindHost(g.bind, g.customBindHost);

    return {
      host,
      port: typeof g.port === 'number' ? g.port : undefined,
      authMode: typeof auth?.mode === 'string' ? auth.mode : undefined,
      tls,
    };
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    const main = configs.find(c => c.filePath.endsWith('openclaw.json'));
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

  getCredentialPaths(installDir: string): string[] {
    return [
      join(installDir, '.env'),
      join(installDir, 'credentials.json'),
      join(installDir, 'auth.json'),
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
        '~/.openclaw/config.yaml',
        '~/.openclaw/config.json',
        '~/.openclaw/gateway.yaml',
        '~/.openclaw/.env',
        // ADV-002 reads the state dir's package.json (installed plugins)
        '~/.openclaw/package.json',
        '~/.clawdbot/openclaw.json',
        '~/.clawdbot/config.yaml',
        '~/.clawdbot/config.json',
        '~/.clawdbot/gateway.yaml',
        '~/.clawdbot/.env',
        '~/.moltbot/openclaw.json',
        '~/.moltbot/config.yaml',
        '~/.moltbot/config.json',
        '~/.moltbot/gateway.yaml',
        '~/.moltbot/.env',
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        '~/.volta/bin/openclaw',
        '~/.local/bin/openclaw',
        '~/.nvm/current/bin/openclaw',
        '~/.npm-global/bin/openclaw',
        '~/bin/openclaw',
      ],
      // Credential stores and conversation memory — permissions only (OC-006),
      // never content
      metadataGlobPatterns: [
        '~/.openclaw/credentials.json',
        '~/.openclaw/auth.json',
        '~/.openclaw/memory.json',
        '~/.openclaw/conversations.db',
      ],
      globPatterns: [
        // package.json of every npm-global copy — versions non-primary copies on remote scans
        ...npmPackageJsonGlobs('openclaw'),
        '~/.openclaw/skills/**',
        '~/.openclaw/custom_skills/**',
        // default workspace's skills/ (a custom agents.defaults.workspace is local-only)
        '~/.openclaw/workspace/skills/**',
        // profile installs (OPENCLAW_PROFILE=<p> → ~/.openclaw-<p>)
        '~/.openclaw-*/openclaw.json',
        '~/.openclaw-*/config.json',
        '~/.openclaw-*/config.yaml',
        '~/.openclaw-*/skills/**',
        '~/.openclaw/agents/*/agent.yaml',
        '~/.openclaw/agents/*/agent.json',
        '~/.openclaw/agents/*/config.yaml',
        '~/.openclaw/agents/*/config.json',
        '~/.openclaw/agents/*/.env',
        '~/.openclaw/agents/*/skills/**',
        // Legacy dirs and the system-wide config load skills the same way
        ...['~/.clawdbot', '~/.moltbot', '/etc/openclaw'].flatMap(d => [`${d}/skills/**`, `${d}/agents/*/skills/**`]),
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
      systemPaths: [
        '/usr/local/bin/openclaw',
        '/opt/homebrew/bin/openclaw',
        '/usr/bin/openclaw',
        '/etc/openclaw',
        '/Applications/OpenClaw.app',
      ],
      systemDirListings: [
        '/etc/openclaw',
      ],
    };
  },
};
