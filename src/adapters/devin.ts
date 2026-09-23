import { basename, join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ParsedConfig } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { stripJsonc } from '../core/jsonc.js';
import { getUserHomeDirs } from './openclaw.js';
import { queryCliVersion } from './version-query.js';

const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/devin',
  '/opt/homebrew/bin/devin',
];

const USER_CLI_RELATIVE_PATHS = [
  '.local/bin/devin',
];

// User-level config filenames under the Devin config dir. Both are JSON with
// comments tolerated (stripped via stripJsonc). `mcpServers` may appear in
// either file, so checks scan every config for it.
const USER_CONFIG_FILES = ['config.json', 'mcp_config.json'];

// Project-level configs under <cwd>/.devin/ — the *.local.json variants are
// user-private overrides, the plain ones are typically VCS-committed.
const PROJECT_CONFIG_FILES = [
  join('.devin', 'config.json'),
  join('.devin', 'config.local.json'),
  join('.devin', 'mcp_config.json'),
  join('.devin', 'mcp_config.local.json'),
];

/**
 * Devin CLI (Cognition) follows the XDG Base Directory spec on POSIX:
 *   $XDG_CONFIG_HOME/devin/config.json        — primary config
 *   $XDG_CONFIG_HOME/devin/mcp_config.json    — MCP server config
 *   $XDG_CONFIG_HOME/devin/AGENTS.md          — global rules/memory
 *   $XDG_DATA_HOME/devin/credentials.toml     — persistent non-expiring API token
 * On Windows both config and credentials live under %APPDATA%\devin\.
 */
export function devinConfigDir(home: string, fs: FSProvider): string {
  if (fs.platform === 'win32') {
    const appData = fs.getEnv('APPDATA');
    return appData?.trim()
      ? join(appData, 'devin')
      : join(home, 'AppData', 'Roaming', 'devin');
  }
  return fs.getEnv('XDG_CONFIG_HOME')?.trim()
    ? join(fs.getEnv('XDG_CONFIG_HOME')!, 'devin')
    : join(home, '.config', 'devin');
}

export function devinDataDir(home: string, fs: FSProvider): string {
  if (fs.platform === 'win32') {
    // Windows keeps credentials.toml alongside the config
    return devinConfigDir(home, fs);
  }
  return fs.getEnv('XDG_DATA_HOME')?.trim()
    ? join(fs.getEnv('XDG_DATA_HOME')!, 'devin')
    : join(home, '.local', 'share', 'devin');
}

async function loadDevinConfig(filePath: string, fs: FSProvider): Promise<ParsedConfig | undefined> {
  try {
    const raw = await fs.readFile(filePath);
    const data = JSON.parse(stripJsonc(raw)) as Record<string, unknown>;
    return { raw, format: 'json', filePath, data };
  } catch {
    return undefined;
  }
}

async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  for (const p of SYSTEM_CLI_PATHS) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS) {
    const p = join(home, rel);
    if (await fs.access(p)) return p;
  }
  try {
    // Exact-name lookup only. Machines with Devin Desktop also ship a
    // `devin-desktop` binary (the editor) — `which devin` cannot match it,
    // and we must never treat it as the CLI.
    const result = fs.execSync('which', ['devin'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}
  return undefined;
}

export const devinAdapter: AgentAdapter = {
  agent: 'devin',
  displayName: 'Devin CLI',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const configDir = devinConfigDir(home, fs);
      const dataDir = devinDataDir(home, fs);
      const cliBinary = await findCLIBinary(home, fs);

      const hasConfigDir = await fs.access(configDir);
      const hasCredentials = await fs.access(join(dataDir, 'credentials.toml'));

      // Positive signal required: config dir, credentials file, or CLI binary.
      if (!hasConfigDir && !hasCredentials && !cliBinary) continue;

      const configFiles: ParsedConfig[] = [];
      if (hasConfigDir) {
        for (const name of USER_CONFIG_FILES) {
          const filePath = join(configDir, name);
          if (!(await fs.access(filePath))) continue;
          const parsed = await loadDevinConfig(filePath, fs);
          if (parsed) configFiles.push(parsed);
        }
      }

      // Devin is a Rust binary — `devin --version` is fast; keep the timeout tight.
      const version = queryCliVersion(cliBinary, fs, { timeoutMs: 3000 });

      installations.push({
        agent: 'devin',
        version,
        installDir: configDir,
        configFiles,
        user: options?.allUsers ? user : undefined,
        cliBinary,
      });
    }

    // Project-level: <cwd>/.devin/{config,mcp_config}[.local].json
    const cwd = process.cwd();
    const projectConfigs: ParsedConfig[] = [];
    for (const rel of PROJECT_CONFIG_FILES) {
      const filePath = join(cwd, rel);
      if (!(await fs.access(filePath))) continue;
      const parsed = await loadDevinConfig(filePath, fs);
      if (parsed) projectConfigs.push(parsed);
    }
    if (projectConfigs.length > 0) {
      installations.push({
        agent: 'devin',
        agentName: `project:${basename(cwd)}`,
        installDir: join(cwd, '.devin'),
        configFiles: projectConfigs,
        profile: 'project',
      });
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    const home = fs.homedir();
    const configDir = devinConfigDir(home, fs);
    return USER_CONFIG_FILES.map(f => join(configDir, f));
  },

  getSkillsDir(_installDir: string): string | undefined {
    // Devin CLI has no fixed skills directory surface.
    return undefined;
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getMemoryFiles(installDir: string): string[] {
    // installDir == the Devin config dir; global rules live next to config.json
    return [join(installDir, 'AGENTS.md')];
  },

  getCredentialPaths(_installDir: string): string[] {
    // installDir is the config dir; credentials.toml lives in the data dir,
    // resolved from the current user's $HOME (XDG-aware). The stored API
    // token is persistent and non-expiring.
    const fs = new LocalFSProvider();
    const home = fs.homedir();
    return [join(devinDataDir(home, fs), 'credentials.toml')];
  },

  getCLICommand(): string {
    return 'devin';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.config/devin/config.json',
        '~/.config/devin/mcp_config.json',
        '~/.config/devin/AGENTS.md',
        '~/.local/share/devin/credentials.toml',
        // User-relative CLI install location — kept in sync with USER_CLI_RELATIVE_PATHS
        '~/.local/bin/devin',
      ],
      globPatterns: [],
      commands: [
        { id: 'devin-which', cmd: 'which', args: ['devin'], timeout: 3000 },
        { id: 'devin-version', cmd: 'devin', args: ['--version'], timeout: 3000 },
      ],
      directoryListings: [
        '~/.config/devin',
        '~/.local/share/devin',
      ],
      envPrefixes: ['DEVIN_', 'XDG_'],
      systemPaths: SYSTEM_CLI_PATHS,
      systemDirListings: [],
    };
  },
};
