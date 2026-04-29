import { join, basename } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { stripJsonc } from '../core/jsonc.js';
import { findNvmBinary, nvmBinaryGlob } from './nvm-binary.js';
import { getUserHomeDirs } from './openclaw.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';

const COPILOT_DIR_NAME = '.copilot';
// Empirically (Copilot CLI 1.0.39 post-login), only `config.json` is
// written under ~/.copilot/. Older docs reference `settings.json` and
// `lsp-config.json`; we still probe for them so the adapter survives a
// future schema change without code edits.
const USER_CONFIG_FILES = ['config.json', 'settings.json', 'lsp-config.json'];
const PROJECT_CONFIG_FILES = ['.mcp.json'];

const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/copilot',
  '/opt/homebrew/bin/copilot',
  '/usr/bin/copilot',
];

const USER_CLI_RELATIVE_PATHS = [
  '.local/bin/copilot',
  '.npm-global/bin/copilot',
  '.volta/bin/copilot',
  '.bun/bin/copilot',
];

async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  for (const p of SYSTEM_CLI_PATHS) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS) {
    const p = join(home, rel);
    if (await fs.access(p)) return p;
  }
  const nvm = await findNvmBinary(home, fs, 'copilot');
  if (nvm) return nvm;
  try {
    const result = fs.execSync('which', ['copilot'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}
  return undefined;
}

/**
 * Copilot CLI's `config.json` opens with a `// User settings belong in
 * settings.json.` comment line — strict JSON parsers will reject it. We
 * read the file ourselves, strip JSONC syntax, then parse. Falls back to
 * the shared `loadConfig` (which auto-detects format) for non-JSONC files.
 */
async function loadFiles(dir: string, names: string[], fs: FSProvider): Promise<ParsedConfig[]> {
  const out: ParsedConfig[] = [];
  for (const name of names) {
    const filePath = join(dir, name);
    if (!(await fs.access(filePath))) continue;
    if (name.endsWith('.json')) {
      try {
        const raw = await fs.readFile(filePath);
        const data = JSON.parse(stripJsonc(raw)) as Record<string, unknown>;
        out.push({ raw, format: 'json', filePath, data });
        continue;
      } catch {}
    }
    try {
      out.push(await loadConfig(filePath, fs));
    } catch {}
  }
  return out;
}

/**
 * Copilot CLI's `model` field appears in either `config.json` or
 * `settings.json` depending on version. We accept either; first match wins.
 * Provider is implicit ("github-copilot" — a routing layer over multiple
 * model providers including Claude and GPT-5).
 */
function extractModels(configs: ParsedConfig[]): ModelRef[] {
  for (const c of configs) {
    if (!c.filePath.endsWith('settings.json') && !c.filePath.endsWith('config.json')) continue;
    const id = c.data.model;
    if (typeof id === 'string' && id.length > 0) {
      return [{ id, provider: 'github-copilot' }];
    }
  }
  return [];
}

export const copilotCliAdapter: AgentAdapter = {
  agent: 'copilot-cli',
  displayName: 'GitHub Copilot CLI',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const copilotDir = join(home, COPILOT_DIR_NAME);
      const cliBinary = await findCLIBinary(home, fs);
      const hasCopilotDir = await fs.access(copilotDir);

      if (!hasCopilotDir && !cliBinary) continue;

      const configFiles = hasCopilotDir ? await loadFiles(copilotDir, USER_CONFIG_FILES, fs) : [];

      const version = queryCliVersion(cliBinary, fs)
        ?? (await readPackageVersion(cliBinary, fs));

      installations.push({
        agent: 'copilot-cli',
        version,
        installDir: copilotDir,
        configFiles,
        models: extractModels(configFiles),
        user: options?.allUsers ? user : undefined,
        cliBinary,
      });
    }

    // Project-level: .mcp.json (workspace MCP servers) and .github/lsp.json
    const cwd = process.cwd();
    const projectConfigs: ParsedConfig[] = [];
    for (const name of PROJECT_CONFIG_FILES) {
      const filePath = join(cwd, name);
      if (!(await fs.access(filePath))) continue;
      try {
        projectConfigs.push(await loadConfig(filePath, fs));
      } catch {}
    }
    const githubLspPath = join(cwd, '.github', 'lsp.json');
    if (await fs.access(githubLspPath)) {
      try {
        projectConfigs.push(await loadConfig(githubLspPath, fs));
      } catch {}
    }
    if (projectConfigs.length > 0) {
      installations.push({
        agent: 'copilot-cli',
        agentName: `project:${basename(cwd)}`,
        installDir: cwd,
        configFiles: projectConfigs,
        profile: 'project',
      });
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    const copilotDir = join(home, COPILOT_DIR_NAME);
    return USER_CONFIG_FILES.map(f => join(copilotDir, f));
  },

  getSkillsDir(_installDir: string): string | undefined {
    // Copilot CLI explicitly stopped loading ~/.claude/ skills/agents in
    // 1.0.36. Custom skills are not a documented surface today.
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
      join(installDir, 'instructions'),
      join(installDir, 'command-history-state.json'),
      join(installDir, 'session-state'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    // Copilot CLI persists auth state inside config.json (and likely shares
    // gh CLI's hosts.yml). settings.json may carry tokens too on older
    // versions. session-state/ holds the active session; command-history-
    // state.json may include past prompts. Surfaced for file-perm checks.
    return [
      join(installDir, 'config.json'),
      join(installDir, 'settings.json'),
      join(installDir, 'command-history-state.json'),
      join(installDir, 'session-state'),
    ];
  },

  getCLICommand(): string {
    return 'copilot';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.copilot/config.json',
        '~/.copilot/settings.json',
        '~/.copilot/lsp-config.json',
        '~/.copilot/command-history-state.json',
        '~/.config/gh/hosts.yml',
        // User-relative CLI install locations
        '~/.local/bin/copilot',
        '~/.npm-global/bin/copilot',
        '~/.volta/bin/copilot',
        '~/.bun/bin/copilot',
      ],
      globPatterns: [
        '~/.copilot/instructions/*.instructions.md',
        '~/.copilot/session-state/*.json',
        nvmBinaryGlob('copilot'),
      ],
      commands: [
        { id: 'copilot-which', cmd: 'which', args: ['copilot'], timeout: 3000 },
        { id: 'copilot-version', cmd: 'copilot', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.copilot',
        '~/.copilot/instructions',
        '~/.copilot/session-state',
        '~/.copilot/logs',
      ],
      envPrefixes: ['COPILOT_', 'GH_', 'GITHUB_'],
      systemPaths: SYSTEM_CLI_PATHS,
      systemDirListings: [],
    };
  },

  // Copilot CLI's gradient runs through MCP/LSP transports and the per-tool
  // approval layer (default: explicit approval; allowAllPermissions disables
  // it). Inversion fires when allowAllPermissions is set or LSP commands
  // contain shell metacharacters — both let untrusted input reach the host.
  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Network / GitHub', trustLevel: 0 },
        { id: 'mcp', label: 'MCP + LSP', trustLevel: 1 },
        { id: 'approval', label: 'Approval Layer', trustLevel: 2 },
        { id: 'host', label: 'Host Filesystem', trustLevel: 3 },
      ],
      components: [
        { id: 'inbound', label: 'Network / GitHub', zone: 'net' },
        {
          id: 'mcp-lsp',
          label: 'MCP + LSP Servers',
          zone: 'mcp',
          guardCheckIds: ['GHC-004', 'GHC-007'],
        },
        {
          id: 'approval',
          label: 'Approval Layer',
          zone: 'approval',
          guardCheckIds: ['GHC-002', 'GHC-005', 'GHC-006'],
        },
        {
          id: 'fs',
          label: 'Host Filesystem',
          zone: 'host',
          guardCheckIds: ['GHC-001', 'GHC-003', 'GHC-008'],
        },
      ],
      edges: [
        { from: 'inbound', to: 'mcp-lsp', kind: 'data' },
        { from: 'mcp-lsp', to: 'approval', kind: 'control' },
        { from: 'approval', to: 'fs', kind: 'data' },
        {
          from: 'inbound',
          to: 'fs',
          label: 'approval bypass',
          triggerCheckIds: ['GHC-002', 'GHC-007'],
        },
      ],
    };
  },
};
