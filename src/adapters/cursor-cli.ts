import { join, basename } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfigIfPresent } from './load-if-present.js';
import { nvmBinaryGlob } from './nvm-binary.js';
import { discoverCliInstalls, retainedVersionGlobs, type RetainedVersionsDir } from './cli-installs.js';
import { getUserHomeDirs } from './openclaw.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';
import { withoutLoadedConfigs, scanCwd } from './project-configs.js';

const CURSOR_DIR_NAME = '.cursor';
// cli-config.json / mcp.json are CLI+IDE shared; permissions.json,
// sandbox.json, and hooks.json are the IDE's machine-wide Auto-run /
// sandbox / hooks configuration (also honored by the CLI since Cursor 3.x).
const USER_CONFIG_FILES = ['cli-config.json', 'mcp.json', 'permissions.json', 'sandbox.json', 'hooks.json'];

// Project-level files under <cwd>/.cursor/
const PROJECT_CONFIG_FILES = ['mcp.json', 'cli.json', 'hooks.json'];

const IDE_APP_BUNDLE = '/Applications/Cursor.app';
const CLI_CONFIG_FILE = 'cli-config.json';
// User skills: ~/.cursor/skills (and skills-cursor/, where the CLI syncs
// installed skills) plus the cross-agent ~/.agents/skills (cursor.com/docs/context/skills)
const USER_SKILL_DIRS = [join(CURSOR_DIR_NAME, 'skills-cursor'), join(CURSOR_DIR_NAME, 'skills'), join('.agents', 'skills')];

/**
 * Directory holding cli-config.json for the scanning user. Cursor CLI
 * configuration reference: "CURSOR_CONFIG_DIR: custom directory path";
 * "XDG_CONFIG_HOME (Linux/BSD): uses $XDG_CONFIG_HOME/cursor/cli-config.json".
 * Only cli-config.json is documented as relocated; the other ~/.cursor files
 * stay put. Another user's environment isn't observable.
 */
export function cursorCliConfigDir(home: string, fs: FSProvider): string | undefined {
  if (home !== fs.homedir()) return undefined;
  const custom = fs.getEnv?.('CURSOR_CONFIG_DIR')?.trim();
  if (custom) return custom === '~' || custom.startsWith('~/') ? join(home, custom.slice(1)) : custom;
  const xdg = fs.platform !== 'darwin' && fs.platform !== 'win32' ? fs.getEnv?.('XDG_CONFIG_HOME')?.trim() : undefined;
  return xdg ? join(xdg, 'cursor') : undefined;
}

// The Cursor IDE (VS Code fork) keeps User/settings.json + globalStorage
// under the per-OS user-data dir. settings.json carries workspace-trust
// config; globalStorage/state.vscdb carries session JWTs in plaintext.
function ideUserDataDir(home: string, fs: FSProvider): string | undefined {
  if (fs.platform === 'darwin') return join(home, 'Library', 'Application Support', 'Cursor');
  if (fs.platform === 'linux') return join(home, '.config', 'Cursor');
  if (fs.platform === 'win32') {
    const appData = fs.getEnv('APPDATA');
    if (appData) return join(appData, 'Cursor');
  }
  return undefined;
}

async function readIdeVersion(fs: FSProvider): Promise<string | undefined> {
  if (fs.platform !== 'darwin') return undefined;
  try {
    const result = await fs.exec(
      'defaults',
      ['read', `${IDE_APP_BUNDLE}/Contents/Info.plist`, 'CFBundleShortVersionString'],
      { timeout: 3000 },
    );
    if (result.exitCode === 0) {
      const v = result.stdout.trim();
      if (v.length > 0) return v;
    }
  } catch {}
  return undefined;
}

// Cursor CLI ships two binary names depending on install path:
//   - install.sh (curl|bash) puts `agent` at ~/.local/bin/agent
//   - npm i -g cursor-cli generally exposes `cursor-agent`
// `agent` is generic enough to collide with other tools, so we prefer
// `cursor-agent` first and only fall back to `agent` when found in a
// known cursor install location (we don't `which agent` blindly).
const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/cursor-agent',
  '/opt/homebrew/bin/cursor-agent',
  '/usr/bin/cursor-agent',
];

const USER_CLI_RELATIVE_PATHS = [
  '.local/bin/cursor-agent',
  '.npm-global/bin/cursor-agent',
  '.volta/bin/cursor-agent',
  '.bun/bin/cursor-agent',
  '.local/bin/agent',
  '.cursor/bin/agent',
];

// install.sh keeps each past version in <ver>/ — each is a runnable copy.
const RETAINED_VERSIONS: RetainedVersionsDir[] = [{ dir: '.local/share/cursor-agent/versions', binary: 'cursor-agent' }];

async function loadFiles(dir: string, names: string[], fs: FSProvider): Promise<ParsedConfig[]> {
  const out: ParsedConfig[] = [];
  for (const name of names) {
    const filePath = join(dir, name);
    const loaded = await loadConfigIfPresent(filePath, fs);
    if (loaded) out.push(loaded);
  }
  return out;
}

/**
 * Cursor CLI persists the active model in `cli-config.json` under both
 * `model.modelId` (display state) and `selectedModel.modelId` (active
 * runtime selection). Prefer `selectedModel.modelId` when present since it
 * reflects the most recent `/model` slash-command selection. Falls back to
 * `model.modelId` for older configs.
 */
function extractModels(configs: ParsedConfig[]): ModelRef[] {
  for (const c of configs) {
    const data = c.data;
    const selected = data.selectedModel as Record<string, unknown> | undefined;
    const selectedId = selected?.modelId;
    if (typeof selectedId === 'string' && selectedId.length > 0) {
      return [{ id: selectedId, provider: 'cursor' }];
    }
    const model = data.model as Record<string, unknown> | undefined;
    const modelId = model?.modelId;
    if (typeof modelId === 'string' && modelId.length > 0) {
      return [{ id: modelId, provider: 'cursor' }];
    }
  }
  return [];
}

export const cursorCliAdapter: AgentAdapter = {
  agent: 'cursor-cli',
  displayName: 'Cursor CLI',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const cursorDir = join(home, CURSOR_DIR_NAME);
      // `agent` is only trusted at the known Cursor paths in USER_CLI_RELATIVE_PATHS.
      const installs = await discoverCliInstalls(home, fs, {
        names: ['cursor-agent'],
        systemPaths: SYSTEM_CLI_PATHS,
        userRelPaths: USER_CLI_RELATIVE_PATHS,
        retainedVersions: RETAINED_VERSIONS,
        version: async (bin, canExec) => (canExec ? queryCliVersion(bin, fs) : undefined)
          ?? (await readPackageVersion(bin, fs)),
      });
      const cliBinary = installs.primary?.path;
      const hasCursorDir = await fs.access(cursorDir);
      // No early exit without ~/.cursor: an IDE-only install (app bundle,
      // user-data settings) is still a Cursor install — decided below.

      const configFiles = hasCursorDir ? await loadFiles(cursorDir, USER_CONFIG_FILES, fs) : [];
      // A relocated cli-config.json replaces the one in ~/.cursor
      const relocatedDir = cursorCliConfigDir(home, fs);
      const relocated = relocatedDir ? await loadFiles(relocatedDir, [CLI_CONFIG_FILE], fs) : [];
      if (relocated.length > 0) {
        const i = configFiles.findIndex(c => c.filePath === join(cursorDir, CLI_CONFIG_FILE));
        if (i >= 0) configFiles.splice(i, 1);
        configFiles.unshift(...relocated);
      }

      // IDE surface: the VS Code-fork user-data dir carries settings.json
      // (workspace trust) and globalStorage/state.vscdb (plaintext session
      // JWTs). Loaded alongside the ~/.cursor configs so IDE-only installs
      // are scanned too.
      const userDataDir = ideUserDataDir(home, fs);
      const ideAppExists = fs.platform === 'darwin' && (await fs.access(IDE_APP_BUNDLE));
      let ideSettingsLoaded = false;
      if (userDataDir) {
        const ideSettings = await loadFiles(join(userDataDir, 'User'), ['settings.json'], fs);
        ideSettingsLoaded = ideSettings.length > 0;
        configFiles.push(...ideSettings);
      }

      // ~/.cursor/ alone (argv.json, extensions/) isn't a CLI signal, but the
      // IDE app bundle or its settings are an IDE install worth scanning.
      if (configFiles.length === 0 && !cliBinary && !ideAppExists) continue;

      // The IDE app versions independently of the CLI (CLI date versions vs
      // IDE semver): with both present the IDE is listed as another install
      // so advisory checks judge each against its own ranges.
      const ideVersion = ideAppExists ? await readIdeVersion(fs) : undefined;
      const version = installs.primary?.version ?? ideVersion;
      const otherInstalls = [...installs.others];
      if (installs.primary?.version && ideVersion && ideVersion !== installs.primary.version) {
        otherInstalls.push({ path: IDE_APP_BUNDLE, version: ideVersion });
      }
      const skillsDirs: string[] = [];
      for (const rel of USER_SKILL_DIRS) {
        if (await fs.access(join(home, rel))) skillsDirs.push(join(home, rel));
      }

      installations.push({
        agent: 'cursor-cli',
        agentName: !cliBinary && (ideAppExists || ideSettingsLoaded) ? 'cursor (IDE)' : undefined,
        version,
        installDir: cursorDir,
        configFiles,
        skillsDir: skillsDirs[0] ?? this.getSkillsDir(cursorDir),
        skillsDirs: skillsDirs.length > 0 ? skillsDirs : undefined,
        models: extractModels(configFiles),
        user: options?.allUsers ? user : undefined,
        cliBinary,
        otherInstalls: otherInstalls.length > 0 ? otherInstalls : undefined,
        appBundle: ideAppExists ? IDE_APP_BUNDLE : undefined,
      });
    }

    // Project-level: .cursor/{mcp,cli,hooks}.json under cwd (project hooks
    // run from the repo in any trusted workspace — cursor.com/docs/agent/hooks)
    const cwd = scanCwd(fs);
    if (!cwd) return installations;
    const projectCursorDir = join(cwd, CURSOR_DIR_NAME);
    if (await fs.access(projectCursorDir)) {
      const projectConfigs = await withoutLoadedConfigs(await loadFiles(projectCursorDir, PROJECT_CONFIG_FILES, fs), installations, fs);
      if (projectConfigs.length > 0) {
        installations.push({
          agent: 'cursor-cli',
          agentName: `project:${basename(cwd)}`,
          installDir: projectCursorDir,
          configFiles: projectConfigs,
          profile: 'project',
        });
      }
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    const home = fs.homedir();
    const cursorDir = join(home, CURSOR_DIR_NAME);
    const relocatedDir = cursorCliConfigDir(home, fs);
    return [
      ...(relocatedDir ? [join(relocatedDir, CLI_CONFIG_FILE)] : []),
      ...USER_CONFIG_FILES.map(f => join(cursorDir, f)),
    ];
  },

  getSkillsDir(installDir: string): string | undefined {
    // Cursor CLI syncs installed skills to ~/.cursor/skills-cursor/
    return join(installDir, 'skills-cursor');
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    return extractModels(configs);
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'rules'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    // Cursor's official docs say credentials are "stored locally" but do not
    // publish a filename. We return the central config files so file-perm
    // checks can still flag world-readable user state. Phase 2 may add the
    // actual credential path once verified on a real install.
    return USER_CONFIG_FILES.map(f => join(installDir, f));
  },

  getCLICommand(): string {
    return 'cursor-agent';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        ...USER_CONFIG_FILES.map(f => `~/.cursor/${f}`),
        // relocated cli-config.json ($CURSOR_CONFIG_DIR twin via RELOCATABLE_TREES)
        '~/.config/cursor/cli-config.json',
        // IDE user-data settings (workspace trust) — macOS and Linux
        '~/Library/Application Support/Cursor/User/settings.json',
        '~/.config/Cursor/User/settings.json',
        // User-relative CLI install locations — both names supported
        '~/.local/bin/cursor-agent',
        '~/.npm-global/bin/cursor-agent',
        '~/.volta/bin/cursor-agent',
        '~/.bun/bin/cursor-agent',
        '~/.local/bin/agent',
        '~/.cursor/bin/agent',
      ],
      globPatterns: [
        '~/.cursor/rules/*.mdc',
        '~/.cursor/extensions/**',
        // Installed skills (getSkillsDir) — SKL/IOC checks read them
        '~/.cursor/skills-cursor/**',
        '~/.cursor/skills/**',
        '~/.agents/skills/**',
        nvmBinaryGlob('cursor-agent'),
      ],
      // IDE state DBs hold session JWTs: CUR-013 / POL-003 need permissions only
      metadataGlobPatterns: [
        ...retainedVersionGlobs(RETAINED_VERSIONS),
        '~/Library/Application Support/Cursor/User/globalStorage/state.vscdb',
        '~/.config/Cursor/User/globalStorage/state.vscdb',
      ],
      commands: [
        { id: 'cursor-ide-version', cmd: 'defaults', args: ['read', `${IDE_APP_BUNDLE}/Contents/Info.plist`, 'CFBundleShortVersionString'], timeout: 3000 },
        { id: 'cursor-agent-which', cmd: 'which', args: ['cursor-agent'], timeout: 3000 },
        { id: 'cursor-agent-version', cmd: 'cursor-agent', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.cursor',
        '~/.cursor/rules',
        '~/.cursor/extensions',
        '~/.cursor/skills-cursor',
        '~/.cursor/skills',
        '~/.agents/skills',
      ],
      envPrefixes: ['CURSOR_'],
      // IDE-only installs are detected by the app bundle (macOS)
      systemPaths: [...SYSTEM_CLI_PATHS, IDE_APP_BUNDLE],
      systemDirListings: [],
    };
  },

  // Cursor's privilege gradient runs through the permission allow/deny layer
  // and the sandbox layer. Inversion fires when sandbox is disabled, an
  // unsafe approval mode is set, or Shell(*) lands in allow without a deny
  // net — any of which lets remote-controlled tool calls reach the host.
  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Network / Cursor Cloud', trustLevel: 0 },
        { id: 'mcp', label: 'MCP Transport', trustLevel: 1 },
        { id: 'perm', label: 'Permission + Sandbox Layer', trustLevel: 2 },
        { id: 'host', label: 'Host Filesystem', trustLevel: 3 },
      ],
      components: [
        {
          id: 'inbound',
          label: 'Network / Remote MCP',
          zone: 'net',
          guardCheckIds: ['CUR-007'],
        },
        {
          id: 'mcp-transport',
          label: 'MCP Transport',
          zone: 'mcp',
          guardCheckIds: ['CUR-006'],
        },
        {
          id: 'permission',
          label: 'Permission Layer',
          zone: 'perm',
          guardCheckIds: ['CUR-001', 'CUR-002', 'CUR-003', 'CUR-005', 'CUR-008', 'CUR-009'],
        },
        {
          id: 'fs',
          label: 'Host Filesystem',
          zone: 'host',
          guardCheckIds: ['CUR-004', 'CUR-010'],
        },
      ],
      edges: [
        { from: 'inbound', to: 'mcp-transport', kind: 'data' },
        { from: 'mcp-transport', to: 'permission', kind: 'control' },
        { from: 'permission', to: 'fs', kind: 'data' },
        {
          from: 'inbound',
          to: 'fs',
          label: 'permission bypass',
          triggerCheckIds: ['CUR-001', 'CUR-002', 'CUR-003'],
        },
      ],
    };
  },
};
