import { join, basename } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { stripJsonc } from '../core/jsonc.js';
import { findNvmBinary, nvmBinaryGlob, npmPackageJsonGlobs } from './nvm-binary.js';
import { getUserHomeDirs } from './openclaw.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';

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

async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  for (const p of SYSTEM_CLI_PATHS) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS) {
    const p = join(home, rel);
    if (await fs.access(p)) return p;
  }
  const nvm = await findNvmBinary(home, fs, 'qwen');
  if (nvm) return nvm;
  try {
    const result = fs.execSync('which', ['qwen'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}
  return undefined;
}

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

/**
 * Qwen Code is multi-provider (OpenAI-compatible / Dashscope / Anthropic /
 * Gemini), so the model id alone doesn't tell us the provider — we look at
 * `security.auth.selectedType` first, then fall back to walking
 * `modelProviders` for the matching id.
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

    // Walk modelProviders if no explicit model.name
    const providers = c.data.modelProviders as Array<Record<string, unknown>> | undefined;
    if (Array.isArray(providers)) {
      const match = providers.find(p => typeof p.id === 'string' && (!provider || (p.id as string).toLowerCase().includes(provider)));
      const fallback = match ?? providers[0];
      if (fallback && typeof fallback.id === 'string') {
        return [{ id: fallback.id as string, provider }];
      }
    }
  }
  return [];
}

export const qwenCodeAdapter: AgentAdapter = {
  agent: 'qwen-code',
  displayName: 'Qwen Code',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const qwenDir = join(home, QWEN_DIR_NAME);
      const cliBinary = await findCLIBinary(home, fs);
      const hasQwenDir = await fs.access(qwenDir);

      if (!hasQwenDir && !cliBinary) continue;

      const configFiles = hasQwenDir ? await loadSettings(qwenDir, fs) : [];

      // A bare ~/.qwen/ with no recognized config files and no `qwen` binary
      // is leftover state, not a CLI install.
      if (configFiles.length === 0 && !cliBinary) continue;

      const version = queryCliVersion(cliBinary, fs)
        ?? (await readPackageVersion(cliBinary, fs, NPM_PACKAGE_NAME));

      installations.push({
        agent: 'qwen-code',
        version,
        installDir: qwenDir,
        configFiles,
        models: extractModels(configFiles),
        user: options?.allUsers ? user : undefined,
        cliBinary,
      });
    }

    // Project-level config (.qwen/settings.json under cwd)
    const cwd = process.cwd();
    const projectQwenDir = join(cwd, QWEN_DIR_NAME);
    if (await fs.access(projectQwenDir)) {
      const projectConfigs = await loadSettings(projectQwenDir, fs);
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
    const home = new LocalFSProvider().homedir();
    const qwenDir = join(home, QWEN_DIR_NAME);
    return [join(qwenDir, SETTINGS_FILE)];
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
      filePaths: [
        '~/.qwen/settings.json',
        '~/.qwen/memory.md',
        '~/.qwen/AGENTS.md',
        '~/.qwen/oauth_creds.json',
        '~/.qwen/mcp-oauth-tokens.json',
        '~/.qwen/google_accounts.json',
        '~/.qwen/installation_id',
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
      systemPaths: SYSTEM_CLI_PATHS,
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
