import { basename, dirname, join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ParsedConfig } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { getUserHomeDirs } from './openclaw.js';
import { discoverCliInstalls, retainedVersionGlobs, type RetainedVersionsDir } from './cli-installs.js';
import { queryCliVersion } from './version-query.js';
import { loadConfigIfPresent } from './load-if-present.js';
import { windsurfPresent } from './windsurf.js';
import { xdgPath } from './env-path.js';
import { scanCwd } from './project-configs.js';

const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/devin',
  '/opt/homebrew/bin/devin',
];

const USER_CLI_RELATIVE_PATHS = [
  '.local/bin/devin',
];

// Devin's updater keeps each version in _versions/<ver>/ — each is a runnable copy.
const RETAINED_VERSIONS: RetainedVersionsDir[] = [{ dir: '.local/share/devin/cli/_versions', binary: 'bin/devin' }];

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

/** Standalone project hooks file — the whole file is the hooks object. */
const PROJECT_HOOKS_FILE = join('.devin', 'hooks.v1.json');

// Skill roots from `devin skills paths` (3000.11.3): <name>/SKILL.md beneath each.
const USER_SKILL_DIRS = [join('.config', 'devin', 'skills'), join('.config', 'cognition', 'skills'), join('.agents', 'skills')];
const PROJECT_SKILL_DIRS = [join('.devin', 'skills'), join('.cognition', 'skills'), join('.agents', 'skills')];

/**
 * Devin finds the project root by walking up from cwd to the nearest `.git`
 * or `.jj` directory and loads `.devin/` from there; nested `.devin/` dirs
 * between root and cwd also apply (closer wins). Returns the dirs to load,
 * root first. Without a repo marker only cwd itself is considered.
 */
export async function projectDirs(cwd: string, fs: FSProvider): Promise<{ root: string; dirs: string[] }> {
  const chain: string[] = [];
  for (let dir = cwd; ; dir = dirname(dir)) {
    chain.push(dir);
    if (await fs.access(join(dir, '.git')) || await fs.access(join(dir, '.jj'))) {
      return { root: dir, dirs: chain.reverse() };
    }
    if (dirname(dir) === dir) break;
  }
  return { root: cwd, dirs: [cwd] };
}

async function existingDirs(base: string, rels: string[], fs: FSProvider): Promise<string[]> {
  const found: string[] = [];
  for (const rel of rels) {
    const dir = join(base, rel);
    if (await fs.access(dir)) found.push(dir);
  }
  return found;
}

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
  const xdg = xdgPath(fs.getEnv('XDG_CONFIG_HOME'));
  return xdg ? join(xdg, 'devin') : join(home, '.config', 'devin');
}

export function devinDataDir(home: string, fs: FSProvider): string {
  if (fs.platform === 'win32') {
    // Windows keeps credentials.toml alongside the config
    return devinConfigDir(home, fs);
  }
  const xdg = xdgPath(fs.getEnv('XDG_DATA_HOME'));
  return xdg ? join(xdg, 'devin') : join(home, '.local', 'share', 'devin');
}

/**
 * Cheap Devin CLI signal shared with the windsurf adapter, which reads the
 * same ~/.config/devin/{config,mcp_config}.json (Devin Desktop 3.x): the
 * persistent credentials file or the CLI at its installer locations. A subset
 * of what detect() accepts, so a file is never dropped by both adapters.
 */
export async function devinCliPresent(home: string, fs: FSProvider): Promise<boolean> {
  const candidates = [
    join(devinDataDir(home, fs), 'credentials.toml'),
    ...USER_CLI_RELATIVE_PATHS.map(rel => join(home, rel)),
    ...SYSTEM_CLI_PATHS,
  ];
  for (const p of candidates) {
    if (await fs.access(p)) return true;
  }
  return false;
}

async function loadDevinConfig(filePath: string, fs: FSProvider): Promise<ParsedConfig | undefined> {
  // The shared loader parses JSON, JSONC and JSON5 and reports an unreadable
  // or unparseable file as CONFIG-LOAD instead of dropping the agent silently
  return loadConfigIfPresent(filePath, fs);
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
      const installs = await discoverCliInstalls(home, fs, {
        // Exact name only — Devin Desktop ships a `devin-desktop` editor binary.
        names: ['devin'],
        systemPaths: SYSTEM_CLI_PATHS,
        userRelPaths: USER_CLI_RELATIVE_PATHS,
        retainedVersions: RETAINED_VERSIONS,
        version: (bin, canExec) => (canExec ? queryCliVersion(bin, fs, { timeoutMs: 3000 }) : undefined),
      });
      const cliBinary = installs.primary?.path;

      const hasConfigDir = await fs.access(configDir);
      const hasCredentials = await fs.access(join(dataDir, 'credentials.toml'));

      // Positive signal required: config dir, credentials file, or CLI binary.
      if (!hasConfigDir && !hasCredentials && !cliBinary) continue;
      // A config dir alone next to Windsurf / Devin Desktop is the desktop
      // app's (3.x writes mcp_config.json/config.json there) — the windsurf
      // install reports it, so it isn't a second, CLI-less Devin install.
      if (!hasCredentials && !cliBinary && await windsurfPresent(home, fs)) continue;

      const configFiles: ParsedConfig[] = [];
      if (hasConfigDir) {
        for (const name of USER_CONFIG_FILES) {
          const filePath = join(configDir, name);
          const parsed = await loadDevinConfig(filePath, fs);
          if (parsed) configFiles.push(parsed);
        }
      }

      // Devin is a Rust binary — `devin --version` is fast; keep the timeout tight.
      const version = installs.primary?.version;
      const skillsDirs = await existingDirs(home, USER_SKILL_DIRS, fs);

      installations.push({
        agent: 'devin',
        version,
        installDir: configDir,
        configFiles,
        skillsDir: skillsDirs[0],
        skillsDirs: skillsDirs.length > 0 ? skillsDirs : undefined,
        user: options?.allUsers ? user : undefined,
        cliBinary,
        otherInstalls: installs.others.length > 0 ? installs.others : undefined,
      });
    }

    // Project-level: <cwd>/.devin/{config,mcp_config}[.local].json
    const cwd = scanCwd(fs);
    if (!cwd) return installations;
    const { root, dirs } = await projectDirs(cwd, fs);
    // Running from $HOME makes project paths coincide with user ones — skip those
    const alreadyLoaded = new Set(installations.flatMap(i => i.configFiles.map(c => c.filePath)));
    const userSkillsDirs = new Set(installations.flatMap(i => i.skillsDirs ?? []));
    const projectConfigs: ParsedConfig[] = [];
    const projectSkillsDirs: string[] = [];
    for (const dir of dirs) {
      for (const rel of PROJECT_CONFIG_FILES) {
        const filePath = join(dir, rel);
        if (alreadyLoaded.has(filePath)) continue;
        const parsed = await loadDevinConfig(filePath, fs);
        if (parsed) projectConfigs.push(parsed);
      }
      const hooksPath = join(dir, PROJECT_HOOKS_FILE);
      {
        const parsed = await loadDevinConfig(hooksPath, fs);
        if (parsed) projectConfigs.push({ ...parsed, data: { hooks: parsed.data } });
      }
      projectSkillsDirs.push(...(await existingDirs(dir, PROJECT_SKILL_DIRS, fs)).filter(d => !userSkillsDirs.has(d)));
    }
    if (projectConfigs.length > 0 || projectSkillsDirs.length > 0) {
      installations.push({
        agent: 'devin',
        agentName: `project:${basename(root)}`,
        installDir: join(root, '.devin'),
        configFiles: projectConfigs,
        skillsDir: projectSkillsDirs[0],
        skillsDirs: projectSkillsDirs.length > 0 ? projectSkillsDirs : undefined,
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

  getSkillsDir(installDir: string): string | undefined {
    // Primary skill root beside the config: ~/.config/devin/skills or <root>/.devin/skills.
    // detect() also records the other roots (cognition/, .agents/) in skillsDirs.
    return join(installDir, 'skills');
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getMemoryFiles(installDir: string): string[] {
    // installDir == the Devin config dir; global rules live next to config.json
    return [join(installDir, 'AGENTS.md')];
  },

  getCredentialPaths(installDir: string, scanFs?: FSProvider): string[] {
    // Project installations (<root>/.devin) hold no credentials; returning the
    // user file here would duplicate POL-003 findings per project.
    if (basename(installDir) === '.devin') return [];
    // installDir is the config dir; credentials.toml lives in the data dir,
    // resolved from the current user's $HOME (XDG-aware). The stored API
    // token is persistent and non-expiring.
    const fs = scanFs ?? new LocalFSProvider();
    const home = fs.homedir();
    return [join(devinDataDir(home, fs), 'credentials.toml')];
  },

  getCLICommand(): string {
    return 'devin';
  },

  getProbeManifest(): ProbeManifest {
    return {
      // Past versions kept by the updater, and the API token store (DEV-002
      // checks its permissions) — existence/permissions only
      metadataGlobPatterns: [...retainedVersionGlobs(RETAINED_VERSIONS), '~/.local/share/devin/credentials.toml'],
      filePaths: [
        '~/.config/devin/config.json',
        '~/.config/devin/mcp_config.json',
        '~/.config/devin/AGENTS.md',
        // Workspace trust list (DEV-008) — paths only
        '~/.local/share/devin/cli/trusted_workspaces.json',
        // User-relative CLI install location — kept in sync with USER_CLI_RELATIVE_PATHS
        '~/.local/bin/devin',
      ],
      // User skill roots — SKL/IOC checks read them
      globPatterns: USER_SKILL_DIRS.map(d => `~/${d}/**`),
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
