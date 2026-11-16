import { join, basename } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { loadConfigIfPresent, pathPresent } from './load-if-present.js';
import { nvmBinaryGlob, npmPackageJsonGlobs } from './nvm-binary.js';
import { discoverCliInstalls } from './cli-installs.js';
import { getUserHomeDirs } from './openclaw.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';
import { envPath } from './env-path.js';
import { scanCwd } from './project-configs.js';

const COPILOT_DIR_NAME = '.copilot';
// Empirically (Copilot CLI 1.0.39 post-login), only `config.json` is
// written under ~/.copilot/. Older docs reference `settings.json` and
// `lsp-config.json`; we still probe for them so the adapter survives a
// future schema change without code edits.
// mcp-config.json: user-level MCP servers (GHC-003/004)
// permissions-config.json: saved per-location tool/directory approvals (GHC-002)
// providers.json: BYOK providers, API keys stored in plain text (GHC-003;
// docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference)
const USER_CONFIG_FILES = ['config.json', 'settings.json', 'lsp-config.json', 'mcp-config.json', 'permissions-config.json', 'providers.json'];
// Project MCP servers live in `.mcp.json` or `.github/mcp.json` (CLI config-dir
// reference); repository settings may carry inline hooks
const PROJECT_CONFIG_FILES = ['.mcp.json', join('.github', 'mcp.json'), join('.github', 'copilot', 'settings.json'), join('.github', 'copilot', 'settings.local.json')];
// Hook files: user-level <config dir>/hooks/*.json, repository .github/hooks/*.json
// (docs.github.com/en/copilot/reference/hooks-reference "Hooks locations")
const USER_HOOKS_DIR = 'hooks';
/** Private store folders under ~/.copilot whose files GHC-001 judges by mode (its PRIVATE_DIRS). */
export const COPILOT_PRIVATE_STORES = ['mcp-oauth-config', 'mcp-secrets', 'command-history-state', 'session-state'] as const;
const PROJECT_HOOKS_DIR = join('.github', 'hooks');
// Personal skills: <config dir>/skills or ~/.agents/skills (GitHub Docs "Adding agent skills")
const SHARED_SKILLS_DIR = join('.agents', 'skills');

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

/**
 * Copilot CLI's `config.json` opens with a `// User settings belong in
 * settings.json.` comment line; the shared loader parses JSONC, and reports
 * an unreadable or unparseable file as CONFIG-LOAD instead of dropping it.
 */
async function loadFiles(dir: string, names: string[], fs: FSProvider): Promise<ParsedConfig[]> {
  const out: ParsedConfig[] = [];
  for (const name of names) {
    const loaded = await loadConfigIfPresent(join(dir, name), fs);
    if (loaded) out.push(loaded);
  }
  return out;
}

async function anyPresent(dir: string, names: string[], fs: FSProvider): Promise<boolean> {
  for (const name of names) {
    if (await pathPresent(join(dir, name), fs)) return true;
  }
  return false;
}

/** Every `*.json` hook file directly in `dir`, sorted by name. */
async function loadHookFiles(dir: string, fs: FSProvider): Promise<ParsedConfig[]> {
  let names: string[];
  try {
    names = (await fs.readdirEntries(dir)).filter(e => e.isFile && e.name.endsWith('.json')).map(e => e.name).sort();
  } catch {
    return [];
  }
  return loadFiles(dir, names, fs);
}

/**
 * BYOK provider registry: $COPILOT_PROVIDERS_CONFIG for the scanning user
 * (config-dir reference), else <config dir>/providers.json.
 */
export function copilotProvidersPath(home: string, copilotDir: string, fs: FSProvider): string {
  return envPath(home === fs.homedir() ? fs.getEnv?.('COPILOT_PROVIDERS_CONFIG') : undefined, home) ?? join(copilotDir, 'providers.json');
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

/**
 * ~/.copilot, or $COPILOT_HOME for the scanning user (it takes precedence over
 * the legacy --config-dir). Another user's environment isn't observable.
 */
export function copilotHome(home: string, fs: FSProvider): string {
  return envPath(home === fs.homedir() ? fs.getEnv?.('COPILOT_HOME') : undefined, home) ?? join(home, COPILOT_DIR_NAME);
}

async function userSkillDirs(home: string, copilotDir: string, fs: FSProvider): Promise<Pick<AgentInstallation, 'skillsDir' | 'skillsDirs'>> {
  const dirs: string[] = [];
  for (const dir of [join(copilotDir, 'skills'), join(home, SHARED_SKILLS_DIR)]) {
    if (await fs.access(dir)) dirs.push(dir);
  }
  return dirs.length > 0 ? { skillsDir: dirs[0], skillsDirs: dirs } : {};
}

export const copilotCliAdapter: AgentAdapter = {
  agent: 'copilot-cli',
  displayName: 'GitHub Copilot CLI',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const copilotDir = copilotHome(home, fs);
      const installs = await discoverCliInstalls(home, fs, {
        names: ['copilot'],
        systemPaths: SYSTEM_CLI_PATHS,
        userRelPaths: USER_CLI_RELATIVE_PATHS,
        version: async (bin, canExec) => (canExec ? queryCliVersion(bin, fs) : undefined)
          ?? (await readPackageVersion(bin, fs, '@github/copilot')),
      });
      const cliBinary = installs.primary?.path;
      const hasCopilotDir = await fs.access(copilotDir);

      if (!hasCopilotDir && !cliBinary) continue;

      const configFiles = hasCopilotDir ? await loadFiles(copilotDir, USER_CONFIG_FILES, fs) : [];
      if (hasCopilotDir) configFiles.push(...await loadHookFiles(join(copilotDir, USER_HOOKS_DIR), fs));
      const providers = copilotProvidersPath(home, copilotDir, fs);
      if (providers !== join(copilotDir, 'providers.json')) {
        const relocated = await loadConfigIfPresent(providers, fs);
        const i = configFiles.findIndex(c => c.filePath === join(copilotDir, 'providers.json'));
        if (i >= 0) configFiles.splice(i, 1);
        if (relocated) configFiles.push(relocated);
      }

      // A bare ~/.copilot/ with no recognized config files and no `copilot`
      // binary is leftover state from another tool (the Copilot IDE extension
      // and `gh copilot` both write under ~/.copilot/ide/), not a CLI install.
      // A recognized config file that is there but not read (unreadable, or
      // ~/.copilot linked into a credential store) still marks an install:
      // its CONFIG-LOAD and GHC-001's store-link finding belong to it.
      if (configFiles.length === 0 && !cliBinary && !(await anyPresent(copilotDir, USER_CONFIG_FILES, fs))) continue;

      const version = installs.primary?.version;

      installations.push({
        agent: 'copilot-cli',
        version,
        installDir: copilotDir,
        configFiles,
        models: extractModels(configFiles),
        user: options?.allUsers ? user : undefined,
        cliBinary,
        otherInstalls: installs.others.length > 0 ? installs.others : undefined,
        ...(await userSkillDirs(home, copilotDir, fs)),
      });
    }

    // Project-level: .mcp.json (workspace MCP servers), .github/lsp.json and
    // .github/copilot-instructions.md — only where Copilot CLI is installed:
    // .mcp.json is also Claude Code's project file, and a repo is not a
    // Copilot install by itself.
    if (installations.length === 0) return installations;
    const cwd = scanCwd(fs);
    if (!cwd) return installations;
    const projectConfigs: ParsedConfig[] = [];
    for (const name of PROJECT_CONFIG_FILES) {
      const filePath = join(cwd, name);
      const loaded = await loadConfigIfPresent(filePath, fs);
      if (loaded) projectConfigs.push(loaded);
    }
    projectConfigs.push(...await loadHookFiles(join(cwd, PROJECT_HOOKS_DIR), fs));
    const githubLspPath = join(cwd, '.github', 'lsp.json');
    if (await fs.access(githubLspPath)) {
      try {
        projectConfigs.push(await loadConfig(githubLspPath, fs));
      } catch {}
    }
    const hasInstructions = await fs.access(join(cwd, '.github', 'copilot-instructions.md'))
      || await fs.access(join(cwd, '.github', 'instructions'));
    if (projectConfigs.length > 0 || hasInstructions) {
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
    const fs = new LocalFSProvider();
    const copilotDir = copilotHome(fs.homedir(), fs);
    return USER_CONFIG_FILES.map(f => join(copilotDir, f));
  },

  getSkillsDir(installDir: string): string | undefined {
    // <config dir>/skills (Copilot stopped loading ~/.claude/ skills in 1.0.36);
    // detect() sets it on the user install only — a project install's dir is the repo
    return join(installDir, 'skills');
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
      join(installDir, 'providers.json'),
      join(installDir, 'command-history-state.json'),
      join(installDir, 'command-history-state'),
      join(installDir, 'session-state'),
      join(installDir, 'session-store.db'),
      join(installDir, 'mcp-oauth-config'),
      join(installDir, 'mcp-secrets'),
    ];
  },

  getCLICommand(): string {
    return 'copilot';
  },

  getProbeManifest(): ProbeManifest {
    return {
      // Past prompts, session state, the cross-session database and the MCP
      // OAuth / secret fallback stores are private — GHC-001 only needs their
      // permissions, so collect existence + mode, never content.
      metadataGlobPatterns: [
        '~/.copilot/command-history-state.json',
        '~/.copilot/command-history-state/*',
        '~/.copilot/session-state/*',
        '~/.copilot/session-store.db',
        '~/.copilot/mcp-oauth-config/*',
        '~/.copilot/mcp-secrets/*',
        // …and one folder level down (session-state/<session id>/events.jsonl)
        '~/.copilot/command-history-state/*/*',
        '~/.copilot/session-state/*/*',
        '~/.copilot/mcp-oauth-config/*/*',
        '~/.copilot/mcp-secrets/*/*',
      ],
      filePaths: [
        '~/.copilot/config.json',
        '~/.copilot/settings.json',
        '~/.copilot/lsp-config.json',
        '~/.copilot/mcp-config.json',
        '~/.copilot/permissions-config.json',
        '~/.copilot/providers.json',
        '${COPILOT_PROVIDERS_CONFIG}',
        '~/.copilot/copilot-instructions.md',
        '~/.config/gh/hosts.yml',
        // User-relative CLI install locations
        '~/.local/bin/copilot',
        '~/.npm-global/bin/copilot',
        '~/.volta/bin/copilot',
        '~/.bun/bin/copilot',
      ],
      globPatterns: [
        // package.json of every npm-global copy — versions non-primary copies on remote scans
        ...npmPackageJsonGlobs('@github/copilot'),
        '~/.copilot/instructions/**/*.instructions.md',
        '~/.copilot/hooks/*.json',
        '~/.copilot/skills/**',
        '~/.agents/skills/**',
        nvmBinaryGlob('copilot'),
      ],
      commands: [
        { id: 'copilot-which', cmd: 'which', args: ['copilot'], timeout: 3000 },
        { id: 'copilot-version', cmd: 'copilot', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.copilot',
        '~/.copilot/instructions',
        '~/.copilot/skills',
        '~/.agents/skills',
        '~/.copilot/session-state',
        '~/.copilot/command-history-state',
        '~/.copilot/mcp-oauth-config',
        '~/.copilot/mcp-secrets',
        '~/.copilot/hooks',
        '~/.copilot/logs',
      ],
      // A store folder linked to a place that isn't the agent's (~/.aws, the
      // home, out of it) — or a folder linked inside one — is recorded as a
      // link only: GHC-001 never walks it, so nothing behind it is collected
      privateStores: [...COPILOT_PRIVATE_STORES].map(d => `~/.copilot/${d}`),
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
