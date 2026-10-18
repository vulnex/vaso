import { join, basename, isAbsolute, resolve } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { nvmBinaryGlob, npmPackageJsonGlobs } from './nvm-binary.js';
import { discoverCliInstalls } from './cli-installs.js';
import { getUserHomeDirs } from './openclaw.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';
import { loadConfigIfPresent } from './load-if-present.js';
import { withoutLoadedConfigs, scanCwd } from './project-configs.js';
import { workspaceTrusted } from './folder-trust.js';

const QWEN_DIR_NAME = '.qwen';
const SETTINGS_FILE = 'settings.json';
const AUTH_FILES = ['oauth_creds.json', 'mcp-oauth-tokens.json', 'google_accounts.json'];
const NPM_PACKAGE_NAME = '@qwen-code/qwen-code';

const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/qwen',
  '/opt/homebrew/bin/qwen',
  '/usr/bin/qwen',
];

const USER_CLI_RELATIVE_PATHS = [
  '.local/bin/qwen',
  '.npm-global/bin/qwen',
  '.volta/bin/qwen',
  '.bun/bin/qwen',
  '.qwen/bin/qwen',
];

async function loadJsoncConfig(filePath: string, fs: FSProvider): Promise<ParsedConfig | undefined> {
  // The shared loader parses JSON, JSONC and JSON5 and reports an unreadable
  // or unparseable file as CONFIG-LOAD instead of dropping the agent silently
  return loadConfigIfPresent(filePath, fs);
}

async function loadSettings(dir: string, fs: FSProvider): Promise<ParsedConfig[]> {
  const out: ParsedConfig[] = [];
  const filePath = join(dir, SETTINGS_FILE);
  const parsed = await loadJsoncConfig(filePath, fs);
  if (parsed) out.push(parsed);
  return out;
}

const SYSTEM_SETTINGS_DARWIN = '/Library/Application Support/QwenCode/settings.json';
const SYSTEM_SETTINGS_LINUX = '/etc/qwen-code/settings.json';
const SYSTEM_SETTINGS_WIN32 = 'C:\\ProgramData\\qwen-code\\settings.json';

/**
 * Machine-wide settings, which override user and project settings (Qwen Code
 * settings.md "Configuration layers"): $QWEN_CODE_SYSTEM_SETTINGS_PATH, else a
 * per-OS location. $QWEN_CODE_SYSTEM_DEFAULTS_PATH holds defaults under them.
 */
export function qwenSystemSettingsPaths(fs: FSProvider): string[] {
  const env = (name: string) => fs.getEnv?.(name)?.trim() || undefined;
  const settings = env('QWEN_CODE_SYSTEM_SETTINGS_PATH')
    ?? (fs.platform === 'darwin' ? SYSTEM_SETTINGS_DARWIN : fs.platform === 'win32' ? SYSTEM_SETTINGS_WIN32 : SYSTEM_SETTINGS_LINUX);
  const defaults = env('QWEN_CODE_SYSTEM_DEFAULTS_PATH');
  return defaults ? [settings, defaults] : [settings];
}

/**
 * Qwen Code is multi-provider (OpenAI-compatible / Dashscope / Anthropic /
 * Gemini), so the model id alone doesn't tell us the provider — we look at
 * `security.auth.selectedType` first, then fall back to `modelProviders`.
 * `modelProviders` is an object keyed by auth type, each holding an array of
 * model entries (`{ "openai": [{ "id": "qwen3-coder-plus", … }] }`, Qwen
 * settings.md "Model Providers"); the bare-array shape is kept for older
 * configs.
 */
function extractModels(configs: ParsedConfig[]): ModelRef[] {
  for (const c of configs) {
    const security = c.data.security as Record<string, unknown> | undefined;
    const auth = security?.auth as Record<string, unknown> | undefined;
    const provider = (auth?.selectedType as string | undefined)?.toLowerCase();

    const model = c.data.model as Record<string, unknown> | string | undefined;
    let id: string | undefined;
    if (typeof model === 'string') id = model;
    else if (model && typeof (model as Record<string, unknown>).name === 'string') {
      id = (model as Record<string, unknown>).name as string;
    }

    if (id) return [{ id, provider }];

    const providers = c.data.modelProviders;
    if (Array.isArray(providers)) {
      const list = providers as Array<Record<string, unknown>>;
      const match = list.find(p => typeof p.id === 'string' && (!provider || (p.id as string).toLowerCase().includes(provider)));
      const fallback = match ?? list[0];
      if (fallback && typeof fallback.id === 'string') {
        return [{ id: fallback.id as string, provider }];
      }
    } else if (providers && typeof providers === 'object') {
      const byType = Object.entries(providers as Record<string, unknown>)
        .filter((e): e is [string, unknown[]] => Array.isArray(e[1]));
      const selected = byType.find(([type]) => type.toLowerCase() === provider) ?? byType[0];
      const first = selected?.[1].find(
        (m): m is Record<string, unknown> => !!m && typeof m === 'object' && typeof (m as Record<string, unknown>).id === 'string',
      );
      if (selected && first) return [{ id: first.id as string, provider: selected[0].toLowerCase() }];
    }
  }
  return [];
}

/**
 * ~/.qwen, or $QWEN_HOME for the scanning user. Qwen settings.md: QWEN_HOME
 * "customizes the global configuration directory (default: ~/.qwen)",
 * absolute or relative to the working directory, leading `~` expanded.
 * Another user's environment isn't observable.
 */
export function qwenHome(home: string, fs: FSProvider): string {
  const env = home === fs.homedir() ? fs.getEnv?.('QWEN_HOME')?.trim() : undefined;
  if (!env) return join(home, QWEN_DIR_NAME);
  if (env === '~' || env.startsWith('~/')) return join(home, env.slice(1));
  if (isAbsolute(env)) return env;
  // Relative to the working directory — which a remote/snapshot scan doesn't have
  const cwd = scanCwd(fs);
  return cwd ? resolve(cwd, env) : join(home, QWEN_DIR_NAME);
}

/** $QWEN_CODE_TRUSTED_FOLDERS_PATH, else trustedFolders.json in the user's Qwen dir. */
export function qwenTrustedFoldersPath(fs: FSProvider): string {
  return fs.getEnv?.('QWEN_CODE_TRUSTED_FOLDERS_PATH')?.trim() || join(qwenHome(fs.homedir(), fs), 'trustedFolders.json');
}

/**
 * Whether Qwen Code applies `<workspace>/.qwen/settings.json`. Folder trust
 * is off by default (Qwen trusted-folders docs), and then every workspace's
 * settings apply; once enabled, an unmatched folder is untrusted.
 */
export async function qwenWorkspaceTrusted(fs: FSProvider, workspace: string): Promise<boolean> {
  const [system, defaults] = qwenSystemSettingsPaths(fs);
  return workspaceTrusted(fs, {
    workspace,
    // system defaults < user < system (settings.md "Configuration layers")
    settingsFiles: [...(defaults ? [defaults] : []), join(qwenHome(fs.homedir(), fs), SETTINGS_FILE), system],
    enabledByDefault: false,
    trustFile: qwenTrustedFoldersPath(fs),
  });
}

export const qwenCodeAdapter: AgentAdapter = {
  agent: 'qwen-code',
  displayName: 'Qwen Code',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];
    // Machine-wide, so attributed to the first user install only
    const systemSettings: ParsedConfig[] = [];
    for (const path of qwenSystemSettingsPaths(fs)) {
      const parsed = await loadJsoncConfig(path, fs);
      if (parsed) systemSettings.push(parsed);
    }

    for (const { home, user } of userDirs) {
      const qwenDir = qwenHome(home, fs);
      const installs = await discoverCliInstalls(home, fs, {
        names: ['qwen'],
        systemPaths: SYSTEM_CLI_PATHS,
        userRelPaths: USER_CLI_RELATIVE_PATHS,
        version: async (bin, canExec) => (canExec ? queryCliVersion(bin, fs) : undefined)
          ?? (await readPackageVersion(bin, fs, NPM_PACKAGE_NAME)),
      });
      const cliBinary = installs.primary?.path;
      const hasQwenDir = await fs.access(qwenDir);

      if (!hasQwenDir && !cliBinary) continue;

      const configFiles = hasQwenDir ? await loadSettings(qwenDir, fs) : [];
      if (systemSettings.length > 0 && (configFiles.length > 0 || cliBinary)) {
        configFiles.push(...systemSettings.splice(0));
      }

      // A bare ~/.qwen/ with no recognized config files and no `qwen` binary
      // is leftover state, not a CLI install.
      if (configFiles.length === 0 && !cliBinary) continue;

      const version = installs.primary?.version;

      installations.push({
        agent: 'qwen-code',
        version,
        installDir: qwenDir,
        configFiles,
        models: extractModels(configFiles),
        user: options?.allUsers ? user : undefined,
        cliBinary,
        otherInstalls: installs.others.length > 0 ? installs.others : undefined,
      });
    }

    // Project-level config (.qwen/settings.json under cwd). With folder trust
    // on, Qwen ignores it in an untrusted workspace; checks downgrade those
    // findings (qwenWorkspaceTrusted).
    const cwd = scanCwd(fs);
    if (!cwd) return installations;
    const projectQwenDir = join(cwd, QWEN_DIR_NAME);
    if (await fs.access(projectQwenDir)) {
      const projectConfigs = await withoutLoadedConfigs(await loadSettings(projectQwenDir, fs), installations, fs);
      if (projectConfigs.length > 0) {
        installations.push({
          agent: 'qwen-code',
          agentName: `project:${basename(cwd)}`,
          installDir: projectQwenDir,
          configFiles: projectConfigs,
          models: extractModels(projectConfigs),
          profile: 'project',
        });
      }
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    return [join(qwenHome(fs.homedir(), fs), SETTINGS_FILE)];
  },

  getSkillsDir(_installDir: string): string | undefined {
    return undefined;
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    return extractModels(configs);
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'memory.md'),
      // default context file (`context.fileName`, Qwen settings.md)
      join(installDir, 'QWEN.md'),
      join(installDir, 'AGENTS.md'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    return AUTH_FILES.map(f => join(installDir, f));
  },

  getCLICommand(): string {
    return 'qwen';
  },

  getProbeManifest(): ProbeManifest {
    return {
      // OAuth/account token stores — QC-002 checks permissions only
      metadataGlobPatterns: [...AUTH_FILES.map(f => `~/.qwen/${f}`), '~/.qwen/.env'],
      filePaths: [
        '${QWEN_CODE_SYSTEM_SETTINGS_PATH}',
        '${QWEN_CODE_SYSTEM_DEFAULTS_PATH}',
        '~/.qwen/settings.json',
        '~/.qwen/memory.md',
        '~/.qwen/QWEN.md',
        '~/.qwen/AGENTS.md',
        '~/.qwen/installation_id',
        '~/.qwen/trustedFolders.json',
        '${QWEN_CODE_TRUSTED_FOLDERS_PATH}',
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        '~/.local/bin/qwen',
        '~/.npm-global/bin/qwen',
        '~/.volta/bin/qwen',
        '~/.bun/bin/qwen',
        '~/.qwen/bin/qwen',
      ],
      globPatterns: [
        '~/.qwen/commands/*',
        '~/.qwen/extensions/**',
        '~/.qwen/skills/**',
        '~/.qwen/rules/*',
        nvmBinaryGlob('qwen'),
        ...npmPackageJsonGlobs(NPM_PACKAGE_NAME),
      ],
      commands: [
        { id: 'qwen-which', cmd: 'which', args: ['qwen'], timeout: 3000 },
        { id: 'qwen-version', cmd: 'qwen', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.qwen',
        '~/.qwen/commands',
        '~/.qwen/extensions',
        '~/.qwen/skills',
      ],
      envPrefixes: ['QWEN_', 'DASHSCOPE_', 'BAILIAN_'],
      // system settings files ride along so remote scans see them
      systemPaths: [...SYSTEM_CLI_PATHS, SYSTEM_SETTINGS_DARWIN, SYSTEM_SETTINGS_LINUX],
      systemDirListings: [],
    };
  },

  // Qwen mirrors Gemini's gradient but adds an explicit MCP-trust gate
  // (mcpServers.<name>.trust = true bypasses approval). Inversion fires when
  // approvalMode=yolo, MCP-trust is set, or permissions.allow is broad with
  // empty deny — all let untrusted input reach the host without confirmation.
  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Network / Cloud', trustLevel: 0 },
        { id: 'mcp', label: 'MCP Transport', trustLevel: 1 },
        { id: 'approval', label: 'Approval / Permissions', trustLevel: 2 },
        { id: 'host', label: 'Host Filesystem', trustLevel: 3 },
      ],
      components: [
        { id: 'inbound', label: 'Network / Remote MCP', zone: 'net' },
        {
          id: 'mcp-transport',
          label: 'MCP Transport',
          zone: 'mcp',
          guardCheckIds: ['QC-004', 'QC-006', 'QC-007'],
        },
        {
          id: 'approval',
          label: 'Approval / Permissions',
          zone: 'approval',
          guardCheckIds: ['QC-003', 'QC-005', 'QC-008'],
        },
        {
          id: 'fs',
          label: 'Host Filesystem',
          zone: 'host',
          guardCheckIds: ['QC-001', 'QC-002', 'QC-009', 'QC-010'],
        },
      ],
      edges: [
        { from: 'inbound', to: 'mcp-transport', kind: 'data' },
        { from: 'mcp-transport', to: 'approval', kind: 'control' },
        { from: 'approval', to: 'fs', kind: 'data' },
        {
          from: 'inbound',
          to: 'fs',
          label: 'approval bypass',
          triggerCheckIds: ['QC-003', 'QC-004'],
        },
      ],
    };
  },
};
