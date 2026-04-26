import { join, basename, dirname } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { deepMerge } from '../core/utils.js';
import { queryCliVersion } from './version-query.js';

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
 * Get home directories to scan.
 * If allUsers is true and running as root, enumerate all user home dirs.
 * Otherwise return only the current user's home dir.
 */
export async function getUserHomeDirs(allUsers?: boolean, fs?: FSProvider): Promise<Array<{ home: string; user: string }>> {
  const _fs = fs ?? new LocalFSProvider();
  if (allUsers && process.getuid?.() === 0) {
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
 * Get OpenClaw config directories for a given home directory,
 * optionally including profile-specific directories.
 */
function getSearchDirs(home: string, profile?: string, fs?: FSProvider): string[] {
  const dirs = [
    join(home, '.openclaw'),
    join(home, '.clawdbot'),
    join(home, '.moltbot'),
  ];

  if (profile) {
    dirs.unshift(join(home, `.openclaw-${profile}`));
  }

  if (process.env.OPENCLAW_HOME) {
    dirs.unshift(process.env.OPENCLAW_HOME);
  }

  // System-wide config (only once, not per-user)
  const currentHome = fs ? fs.homedir() : new LocalFSProvider().homedir();
  if (home === currentHome) {
    dirs.push('/etc/openclaw');
  }

  return dirs;
}

/**
 * Find the first existing CLI binary path.
 */
async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  // Check system paths
  for (const p of SYSTEM_CLI_PATHS) {
    if (await fs.access(p)) return p;
  }

  // Check user-relative paths
  for (const rel of USER_CLI_RELATIVE_PATHS) {
    const p = join(home, rel);
    if (await fs.access(p)) return p;
  }

  // Try which/command lookup
  try {
    const result = fs.execSync('which', ['openclaw'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {
    // Not in PATH
  }

  return undefined;
}

/**
 * Check for macOS .app bundle.
 */
async function findAppBundle(fs: FSProvider): Promise<string | undefined> {
  if (fs.platform !== 'darwin') return undefined;
  if (await fs.access(APP_BUNDLE_PATH)) return APP_BUNDLE_PATH;
  return undefined;
}

/**
 * Read version from the package.json nearest to a CLI binary's resolved path.
 * Works for npm-installed binaries (global or local).
 */
async function readPackageVersion(binary: string, fs: FSProvider): Promise<string | undefined> {
  try {
    const resolved = await fs.realpath(binary);
    // Walk up from the binary to find package.json
    let dir = dirname(resolved);
    for (let i = 0; i < 5; i++) {
      const pkgPath = join(dir, 'package.json');
      try {
        const raw = await fs.readFile(pkgPath);
        const pkg = JSON.parse(raw);
        if (pkg.version && /^\d+\.\d+\.\d+/.test(pkg.version)) {
          return pkg.version;
        }
      } catch {
        // No package.json here, walk up
      }
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  } catch {
    // realpath or read failed
  }
  return undefined;
}

export const openclawAdapter: AgentAdapter = {
  agent: 'openclaw',
  displayName: 'OpenClaw',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const profile = process.env.OPENCLAW_PROFILE || undefined;
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const appBundle = await findAppBundle(fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const cliBinary = await findCLIBinary(home, fs);
      const searchDirs = getSearchDirs(home, profile, fs);
      let foundForUser = false;

      for (const dir of searchDirs) {
        if (!(await fs.access(dir))) continue;

        const configFiles = [];
        for (const filename of CONFIG_FILENAMES) {
          const filePath = join(dir, filename);
          try {
            const config = await loadConfig(filePath, fs);
            configFiles.push(config);
          } catch {
            // File doesn't exist or can't be parsed
          }
        }

        if (configFiles.length === 0) continue;

        // Extract version from openclaw.json, fallback to CLI, then package.json
        const mainConfig = configFiles.find(c => c.filePath.endsWith('openclaw.json'));
        const version = (mainConfig?.data?.version as string)
          ?? (cliBinary ? queryCliVersion(cliBinary, fs, { argSets: [['--version'], ['version']] }) : undefined)
          ?? (cliBinary ? await readPackageVersion(cliBinary, fs) : undefined);
        const skillsDir = this.getSkillsDir(dir);

        // Merge all config data to extract gateway info
        const merged: Record<string, unknown> = {};
        for (const c of configFiles) {
          Object.assign(merged, c.data);
        }

        const globalInstallation: AgentInstallation = {
          agent: 'openclaw',
          version,
          installDir: dir,
          configFiles,
          skillsDir,
          gateway: this.getGatewayInfo(merged),
          profile,
          user: options?.allUsers ? user : undefined,
          appBundle,
          cliBinary,
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
                profile,
                user: options?.allUsers ? user : undefined,
                appBundle,
                cliBinary,
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
          configFiles: [],
          cliBinary,
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
    const dirs = getSearchDirs(_fs.homedir(), process.env.OPENCLAW_PROFILE || undefined, _fs);
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
    const gw = config.gateway as Record<string, unknown> | undefined;
    if (!gw) return undefined;

    return {
      host: gw.host as string | undefined,
      port: gw.port as number | undefined,
      authMode: (gw.auth as Record<string, unknown>)?.mode as string | undefined,
      tls: gw.tls as boolean | undefined,
    };
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
        '~/.openclaw/openclaw.json',
        '~/.openclaw/config.yaml',
        '~/.openclaw/config.json',
        '~/.openclaw/gateway.yaml',
        '~/.openclaw/.env',
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
        '~/.openclaw/credentials.json',
        '~/.openclaw/auth.json',
        '~/.openclaw/memory.json',
        '~/.openclaw/conversations.db',
      ],
      globPatterns: [
        '~/.openclaw/skills/**',
        '~/.openclaw/custom_skills/**',
        '~/.openclaw/agents/*/agent.yaml',
        '~/.openclaw/agents/*/agent.json',
        '~/.openclaw/agents/*/config.yaml',
        '~/.openclaw/agents/*/config.json',
        '~/.openclaw/agents/*/.env',
        '~/.openclaw/agents/*/skills/**',
      ],
      commands: [
        { id: 'openclaw-which', cmd: 'which', args: ['openclaw'], timeout: 3000 },
        { id: 'openclaw-version', cmd: 'openclaw', args: ['--version'], timeout: 3000 },
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
