import { join, basename } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { stripJsonc } from '../core/jsonc.js';
import { nvmBinaryGlob, npmPackageJsonGlobs } from './nvm-binary.js';
import { discoverCliInstalls } from './cli-installs.js';
import { getUserHomeDirs } from './openclaw.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';
import { withoutLoadedConfigs } from './project-configs.js';

const GEMINI_DIR_NAME = '.gemini';
const SETTINGS_FILE = 'settings.json';
const AUTH_FILES = ['oauth_creds.json', 'google_accounts.json', 'mcp-oauth-tokens.json', 'a2a-oauth-tokens.json'];
const NPM_PACKAGE_NAME = '@google/gemini-cli';

const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/gemini',
  '/opt/homebrew/bin/gemini',
  '/usr/bin/gemini',
];

const USER_CLI_RELATIVE_PATHS = [
  '.local/bin/gemini',
  '.npm-global/bin/gemini',
  '.volta/bin/gemini',
  '.bun/bin/gemini',
];

async function loadJsoncConfig(filePath: string, fs: FSProvider): Promise<ParsedConfig | undefined> {
  try {
    const raw = await fs.readFile(filePath);
    const data = JSON.parse(stripJsonc(raw)) as Record<string, unknown>;
    return { raw, format: 'json', filePath, data };
  } catch {
    return undefined;
  }
}

async function loadSettings(dir: string, fs: FSProvider): Promise<ParsedConfig[]> {
  const out: ParsedConfig[] = [];
  const filePath = join(dir, SETTINGS_FILE);
  if (!(await fs.access(filePath))) return out;
  const parsed = await loadJsoncConfig(filePath, fs);
  if (parsed) out.push(parsed);
  return out;
}

const SYSTEM_SETTINGS_DARWIN = '/Library/Application Support/GeminiCli/settings.json';
const SYSTEM_SETTINGS_LINUX = '/etc/gemini-cli/settings.json';
const SYSTEM_SETTINGS_WIN32 = 'C:\\ProgramData\\gemini-cli\\settings.json';

/**
 * System-wide settings file, which overrides user and workspace settings
 * (gemini-cli settings.ts getSystemSettingsPath: $GEMINI_CLI_SYSTEM_SETTINGS_PATH,
 * else a per-OS location).
 */
export function geminiSystemSettingsPath(fs: FSProvider): string {
  const env = fs.getEnv?.('GEMINI_CLI_SYSTEM_SETTINGS_PATH')?.trim();
  if (env) return env;
  if (fs.platform === 'darwin') return SYSTEM_SETTINGS_DARWIN;
  if (fs.platform === 'win32') return SYSTEM_SETTINGS_WIN32;
  return SYSTEM_SETTINGS_LINUX;
}

/**
 * Walk ~/.gemini/tmp/<project-id>/chats/session-*.jsonl, collect every
 * candidate, pick the lex-greatest filename (timestamp prefix sorts
 * chronologically), and return the most recent `"model":"..."` from its
 * message lines. `/model set` without `--persist` only updates this transcript,
 * not settings.json — so this is the empirical "what model is the user
 * actually running" when settings.json has no model.name.
 */
async function findLatestSessionModel(fs: FSProvider, tmpDir: string): Promise<string | undefined> {
  let projects;
  try {
    projects = await fs.readdirEntries(tmpDir);
  } catch {
    return undefined;
  }
  let latestPath: string | undefined;
  let latestName = '';
  for (const proj of projects) {
    if (!proj.isDirectory) continue;
    const chatsDir = `${tmpDir}/${proj.name}/chats`;
    let entries;
    try {
      entries = await fs.readdirEntries(chatsDir);
    } catch {
      continue;
    }
    for (const e of entries) {
      if (!e.isFile) continue;
      if (!e.name.startsWith('session-') || !e.name.endsWith('.jsonl')) continue;
      if (e.name > latestName) {
        latestName = e.name;
        latestPath = `${chatsDir}/${e.name}`;
      }
    }
  }
  if (!latestPath) return undefined;
  let content;
  try {
    content = await fs.readFile(latestPath);
  } catch {
    return undefined;
  }
  const re = /"model":"([^"]+)"/g;
  let last: string | undefined;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) last = m[1];
  return last;
}

/**
 * Pull the model from settings.json. Gemini stores it under `model.name`
 * (current schema) but also recognizes a top-level `model` string in older
 * configs. Resolution order matches the CLI's own (config.ts:853):
 * `GEMINI_MODEL` env > `settings.model.name` > session-jsonl tail.
 * Default fallback `auto-gemini-3` is intentionally NOT surfaced — it only
 * indicates the user hasn't configured anything.
 */
async function extractModels(configs: ParsedConfig[], fs?: FSProvider): Promise<ModelRef[]> {
  const envModel = fs?.getEnv?.('GEMINI_MODEL');
  if (envModel) return [{ id: envModel, provider: 'google', via: 'GEMINI_MODEL' }];

  for (const c of configs) {
    const model = c.data.model as Record<string, unknown> | string | undefined;
    if (typeof model === 'string' && model.length > 0) {
      return [{ id: model, provider: 'google' }];
    }
    if (model && typeof model === 'object') {
      const name = (model as Record<string, unknown>).name;
      if (typeof name === 'string' && name.length > 0) {
        return [{ id: name, provider: 'google' }];
      }
    }
  }

  if (fs) {
    const tmpDir = join(geminiHome(fs.homedir(), fs), 'tmp');
    const found = await findLatestSessionModel(fs, tmpDir);
    if (found) return [{ id: found, provider: 'google', via: 'last session' }];
  }
  return [];
}

/**
 * ~/.gemini, or $GEMINI_CLI_HOME/.gemini for the scanning user (the variable
 * replaces the home directory Gemini CLI keeps .gemini in). Another user's
 * environment isn't observable.
 */
export function geminiHome(home: string, fs: FSProvider): string {
  const env = home === fs.homedir() ? fs.getEnv?.('GEMINI_CLI_HOME')?.trim() : undefined;
  if (!env) return join(home, GEMINI_DIR_NAME);
  return join(env === '~' || env.startsWith('~/') ? join(home, env.slice(1)) : env, GEMINI_DIR_NAME);
}

export const geminiAdapter: AgentAdapter = {
  agent: 'gemini-cli',
  displayName: 'Gemini CLI',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];
    // Machine-wide, so attributed to the first user install only
    const systemPath = geminiSystemSettingsPath(fs);
    let systemSettings: ParsedConfig | undefined = (await fs.access(systemPath))
      ? await loadJsoncConfig(systemPath, fs)
      : undefined;

    for (const { home, user } of userDirs) {
      const geminiDir = geminiHome(home, fs);
      const installs = await discoverCliInstalls(home, fs, {
        names: ['gemini'],
        systemPaths: SYSTEM_CLI_PATHS,
        userRelPaths: USER_CLI_RELATIVE_PATHS,
        version: async (bin, canExec) => (canExec ? queryCliVersion(bin, fs) : undefined)
          ?? (await readPackageVersion(bin, fs, NPM_PACKAGE_NAME)),
      });
      const cliBinary = installs.primary?.path;
      const hasGeminiDir = await fs.access(geminiDir);

      if (!hasGeminiDir && !cliBinary) continue;

      const configFiles = hasGeminiDir ? await loadSettings(geminiDir, fs) : [];
      if (systemSettings && (configFiles.length > 0 || cliBinary)) {
        configFiles.push(systemSettings);
        systemSettings = undefined;
      }

      // A bare ~/.gemini/ with no recognized config files and no `gemini`
      // binary is leftover state from another tool (Google's IDE extensions
      // and other Gemini-branded tooling all touch this path), not a CLI
      // install.
      if (configFiles.length === 0 && !cliBinary) continue;

      const version = installs.primary?.version;

      installations.push({
        agent: 'gemini-cli',
        version,
        installDir: geminiDir,
        configFiles,
        models: await extractModels(configFiles, fs),
        user: options?.allUsers ? user : undefined,
        cliBinary,
        otherInstalls: installs.others.length > 0 ? installs.others : undefined,
      });
    }

    // Project-level config in current working directory (Gemini reads
    // ./.gemini/settings.json when the workspace is trusted).
    const cwd = process.cwd();
    const projectGeminiDir = join(cwd, GEMINI_DIR_NAME);
    if (await fs.access(projectGeminiDir)) {
      const projectConfigs = withoutLoadedConfigs(await loadSettings(projectGeminiDir, fs), installations);
      if (projectConfigs.length > 0) {
        installations.push({
          agent: 'gemini-cli',
          agentName: `project:${basename(cwd)}`,
          installDir: projectGeminiDir,
          configFiles: projectConfigs,
          models: await extractModels(projectConfigs, fs),
          profile: 'project',
        });
      }
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    return [join(geminiHome(fs.homedir(), fs), SETTINGS_FILE), geminiSystemSettingsPath(fs)];
  },

  getSkillsDir(installDir: string): string | undefined {
    // Gemini "extensions/skills" live under ~/.gemini/extensions and
    // ~/.gemini/agents (markdown-defined sub-agents). Skill code analysis
    // doesn't apply the same way as Claude Code skills (which are JS), so
    // return undefined for the generic skills-dir scan.
    void installDir;
    return undefined;
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  async getModels(configs: ParsedConfig[], fs?: FSProvider): Promise<ModelRef[]> {
    return extractModels(configs, fs);
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'memory.md'),
      join(installDir, 'GEMINI.md'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    return AUTH_FILES.map(f => join(installDir, f));
  },

  getCLICommand(): string {
    return 'gemini';
  },

  getProbeManifest(): ProbeManifest {
    return {
      // Chat transcripts are private conversation content — existence only.
      // (Locally the latest one still supplies the active model when
      // settings.json has none; remote scans rely on settings.json.)
      metadataGlobPatterns: [
        '~/.gemini/tmp/*/chats/session-*.jsonl',
        // OAuth/account token stores — GEM-002 checks permissions only
        ...AUTH_FILES.map(f => `~/.gemini/${f}`),
        '~/.gemini/.env',
      ],
      filePaths: [
        '~/.gemini/settings.json',
        '~/.gemini/memory.md',
        '~/.gemini/GEMINI.md',
        '~/.gemini/installation_id',
        '~/.gemini/trustedFolders.json',
        // relocated trust file / system settings (absolute file paths)
        '${GEMINI_CLI_TRUSTED_FOLDERS_PATH}',
        '${GEMINI_CLI_SYSTEM_SETTINGS_PATH}',
        '~/.gemini/policy_integrity.json',
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        '~/.local/bin/gemini',
        '~/.npm-global/bin/gemini',
        '~/.volta/bin/gemini',
        '~/.bun/bin/gemini',
      ],
      globPatterns: [
        '~/.gemini/agents/*.md',
        '~/.gemini/commands/*',
        '~/.gemini/policies/*',
        '~/.gemini/extensions/**',
        nvmBinaryGlob('gemini'),
        ...npmPackageJsonGlobs(NPM_PACKAGE_NAME),
      ],
      commands: [
        { id: 'gemini-which', cmd: 'which', args: ['gemini'], timeout: 3000 },
        { id: 'gemini-version', cmd: 'gemini', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.gemini',
        '~/.gemini/agents',
        '~/.gemini/commands',
        '~/.gemini/extensions',
        '~/.gemini/policies',
        '~/.gemini/tmp',
      ],
      envPrefixes: ['GEMINI_', 'GOOGLE_'],
      systemPaths: [...SYSTEM_CLI_PATHS, SYSTEM_SETTINGS_DARWIN, SYSTEM_SETTINGS_LINUX],
      systemDirListings: [],
    };
  },

  // Gemini's privilege gradient: untrusted network → MCP transport → tool
  // approval layer (defaultApprovalMode + tools.allowed) → host filesystem.
  // Inversion fires when YOLO is unguarded or `tools.allowed` is overbroad,
  // letting prompt-injected tool calls reach the host without confirmation.
  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Network / Cloud', trustLevel: 0 },
        { id: 'mcp', label: 'MCP Transport', trustLevel: 1 },
        { id: 'approval', label: 'Approval Layer', trustLevel: 2 },
        { id: 'host', label: 'Host Filesystem', trustLevel: 3 },
      ],
      components: [
        { id: 'inbound', label: 'Network / Remote MCP', zone: 'net' },
        {
          id: 'mcp-transport',
          label: 'MCP Transport',
          zone: 'mcp',
          guardCheckIds: ['GEM-007', 'GEM-008'],
        },
        {
          id: 'approval',
          label: 'Approval / Sandbox',
          zone: 'approval',
          guardCheckIds: ['GEM-003', 'GEM-004', 'GEM-005', 'GEM-006', 'GEM-009'],
        },
        {
          id: 'fs',
          label: 'Host Filesystem',
          zone: 'host',
          guardCheckIds: ['GEM-001', 'GEM-002', 'GEM-010'],
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
          triggerCheckIds: ['GEM-003', 'GEM-004'],
        },
      ],
    };
  },
};
