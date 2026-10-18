import { join, basename } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { loadConfigIfPresent } from './load-if-present.js';
import { nvmBinaryGlob, npmPackageJsonGlobs } from './nvm-binary.js';
import { discoverCliInstalls, retainedVersionGlobs, type RetainedVersionsDir } from './cli-installs.js';
import { getUserHomeDirs } from './openclaw.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';
import { withoutLoadedConfigs, scanCwd } from './project-configs.js';
import { envPath } from './env-path.js';

const CLAUDE_DIR_NAME = '.claude';
const SETTINGS_FILES = ['settings.json', 'settings.local.json'];
const ROOT_STATE_FILE = '.claude.json';
const NPM_PACKAGE_NAME = '@anthropic-ai/claude-code';
// Project-scoped MCP servers, shared through the repo
const PROJECT_MCP_FILE = '.mcp.json';

/** Project memory Claude Code loads from a repo (code.claude.com/docs/en/memory). */
function projectMemoryPaths(repo: string): string[] {
  return [
    join(repo, 'CLAUDE.md'),
    join(repo, 'CLAUDE.local.md'),
    join(repo, CLAUDE_DIR_NAME, 'CLAUDE.md'),
    join(repo, CLAUDE_DIR_NAME, 'rules'),
  ];
}

const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/claude',
  '/opt/homebrew/bin/claude',
  '/usr/bin/claude',
];

const USER_CLI_RELATIVE_PATHS = [
  '.local/bin/claude',
  '.npm-global/bin/claude',
  '.volta/bin/claude',
  '.claude/local/claude',
  '.bun/bin/claude',
];

// Native installer keeps past versions as <ver> binaries — each is a runnable copy.
const RETAINED_VERSIONS: RetainedVersionsDir[] = [{ dir: '.local/share/claude/versions' }];

async function loadSettingsFiles(dir: string, fs: FSProvider) {
  const configFiles = [];
  for (const filename of SETTINGS_FILES) {
    const filePath = join(dir, filename);
    const loaded = await loadConfigIfPresent(filePath, fs);
    if (loaded) configFiles.push(loaded);
  }
  return configFiles;
}

/**
 * Infer the Claude model the user is most likely running on by default, based
 * on persisted plan/migration flags in ~/.claude.json. Returned with
 * via='plan default' so callers can present it as a derived hint rather than
 * an explicit setting. Returns undefined when no plan signal is available.
 */
function inferPlanDefaultModel(rootState?: Record<string, unknown>): ModelRef | undefined {
  if (!rootState) return undefined;
  const flag = (k: string) => rootState[k] === true;
  // Migration flags Claude Code sets when it has moved a user's defaults
  // forward to a new generation. Most-recent wins.
  const opusVersion = flag('opus47MigrationComplete')
    ? '4.7'
    : flag('opus45MigrationComplete') || flag('opusProMigrationComplete')
      ? '4.5'
      : undefined;
  const sonnetVersion = flag('sonnet1m45MigrationComplete') || flag('sonnet45MigrationComplete')
    ? '4.5'
    : undefined;
  const onOpusPlan = flag('hasOpusPlanDefault') || flag('opusProMigrationComplete');
  if (onOpusPlan && opusVersion) {
    return { id: `claude-opus-${opusVersion}`, provider: 'anthropic', via: 'plan default' };
  }
  if (sonnetVersion) {
    return { id: `claude-sonnet-${sonnetVersion}`, provider: 'anthropic', via: 'plan default' };
  }
  if (opusVersion) {
    return { id: `claude-opus-${opusVersion}`, provider: 'anthropic', via: 'plan default' };
  }
  return undefined;
}

/**
 * ~/.claude and ~/.claude.json, or $CLAUDE_CONFIG_DIR (which holds both) for
 * the scanning user. Another user's environment isn't observable, so
 * --all-users homes use the defaults.
 */
export function claudeConfigPaths(home: string, fs: FSProvider): { claudeDir: string; rootStateFile: string } {
  const dir = envPath(home === fs.homedir() ? fs.getEnv?.('CLAUDE_CONFIG_DIR') : undefined, home);
  if (!dir) return { claudeDir: join(home, CLAUDE_DIR_NAME), rootStateFile: join(home, ROOT_STATE_FILE) };
  return { claudeDir: dir, rootStateFile: join(dir, ROOT_STATE_FILE) };
}

export const claudeCodeAdapter: AgentAdapter = {
  agent: 'claude-code',
  displayName: 'Claude Code',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const { claudeDir, rootStateFile } = claudeConfigPaths(home, fs);

      const installs = await discoverCliInstalls(home, fs, {
        names: ['claude'],
        systemPaths: SYSTEM_CLI_PATHS,
        userRelPaths: USER_CLI_RELATIVE_PATHS,
        retainedVersions: RETAINED_VERSIONS,
        version: async (bin, canExec) => (canExec ? queryCliVersion(bin, fs) : undefined)
          ?? (await readPackageVersion(bin, fs, NPM_PACKAGE_NAME)),
      });
      const cliBinary = installs.primary?.path;
      const hasClaudeDir = await fs.access(claudeDir);
      const hasRootState = await fs.access(rootStateFile);

      if (!hasClaudeDir && !hasRootState && !cliBinary) continue;

      const configFiles = hasClaudeDir ? await loadSettingsFiles(claudeDir, fs) : [];

      if (hasRootState) {
        try {
          configFiles.push(await loadConfig(rootStateFile, fs));
        } catch {}
      }

      // A bare ~/.claude/ with no settings files, no successfully-parsed
      // ~/.claude.json, and no `claude` binary is leftover state, not an
      // install. (`hasRootState` alone counted earlier, but if loadConfig
      // threw, configFiles is still empty and there's nothing to scan.)
      if (configFiles.length === 0 && !cliBinary) continue;

      const version = installs.primary?.version;
      const skillsDir = this.getSkillsDir(claudeDir);

      installations.push({
        agent: 'claude-code',
        version,
        installDir: claudeDir,
        configFiles,
        skillsDir,
        models: await this.getModels?.(configFiles, fs),
        user: options?.allUsers ? user : undefined,
        cliBinary,
        otherInstalls: installs.others.length > 0 ? installs.others : undefined,
      });
    }

    // Project-level config in the current working directory. Claude Code
    // reads <repo>/CLAUDE.md, CLAUDE.local.md, .claude/rules/ and the shared
    // <repo>/.mcp.json whether or not the repo has .claude/settings*.json, so
    // any of them makes the project scannable. Running from $HOME makes
    // <cwd>/.claude the user dir itself — already covered above.
    const cwd = scanCwd(fs);
    if (!cwd) return installations;
    const projectClaudeDir = join(cwd, CLAUDE_DIR_NAME);
    if (!installations.some(i => i.installDir === projectClaudeDir)) {
      const projectConfigs = await withoutLoadedConfigs([
        ...(await fs.access(projectClaudeDir) ? await loadSettingsFiles(projectClaudeDir, fs) : []),
        ...[await loadConfigIfPresent(join(cwd, PROJECT_MCP_FILE), fs)].filter(c => c !== undefined),
      ], installations, fs);
      const hasMemory = (await Promise.all(projectMemoryPaths(cwd).map(p => fs.access(p)))).some(Boolean);
      if (projectConfigs.length > 0 || hasMemory) {
        // The project runs under the scanning user's claude — its version
        // decides how project settings are honored (CC-001)
        const self = installations.find(i => i.installDir === claudeConfigPaths(fs.homedir(), fs).claudeDir);
        installations.push({
          agent: 'claude-code',
          agentName: `project:${basename(cwd)}`,
          version: self?.version,
          installDir: projectClaudeDir,
          configFiles: projectConfigs,
          skillsDir: this.getSkillsDir(projectClaudeDir),
          models: await this.getModels?.(projectConfigs, fs),
          profile: 'project',
        });
      }
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    const { claudeDir, rootStateFile } = claudeConfigPaths(fs.homedir(), fs);
    return [
      ...SETTINGS_FILES.map(f => join(claudeDir, f)),
      rootStateFile,
    ];
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getModels(configs: ParsedConfig[], fs?: FSProvider): ModelRef[] {
    // Claude Code rarely persists the active model: the `/model` runtime
    // command doesn't write back to settings.json, so most users have no
    // explicit `model` field. We layer signals from most-explicit to most-
    // inferred and stop at the first that yields anything.
    //
    //   1. settings.{json,local.json}.model + .fallbackModel  (explicit)
    //   2. ~/.claude.json top-level `model` field             (rare)
    //   3. ANTHROPIC_MODEL env var                            (explicit override)
    //   4. Plan-default inference from migration flags        (best-effort)
    const out: ModelRef[] = [];

    for (const file of configs) {
      if (!file.filePath.endsWith('settings.json') && !file.filePath.endsWith('settings.local.json')) continue;
      const id = file.data?.model as string | undefined;
      if (id) out.push({ id, provider: 'anthropic' });
      const fallback = file.data?.fallbackModel as string | undefined;
      if (fallback && fallback !== id) out.push({ id: fallback, provider: 'anthropic', via: 'fallback' });
    }
    if (out.length > 0) return out;

    const rootState = configs.find(c => c.filePath.endsWith(ROOT_STATE_FILE));
    const rootModel = rootState?.data?.model as string | undefined;
    if (rootModel) return [{ id: rootModel, provider: 'anthropic' }];

    const envModel = fs?.getEnv?.('ANTHROPIC_MODEL');
    if (envModel) return [{ id: envModel, provider: 'anthropic', via: 'ANTHROPIC_MODEL' }];

    const inferred = inferPlanDefaultModel(rootState?.data);
    return inferred ? [inferred] : [];
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'CLAUDE.md'),
      join(installDir, 'projects'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    return [
      join(installDir, '.credentials.json'),
      join(installDir, 'settings.json'),
      join(installDir, 'settings.local.json'),
    ];
  },

  getCLICommand(): string {
    return 'claude';
  },

  getProbeManifest(): ProbeManifest {
    return {
      // Past versions kept by the updater — existence only
      // OAuth token store — permissions only, never content
      metadataGlobPatterns: [...retainedVersionGlobs(RETAINED_VERSIONS), '~/.claude/.credentials.json'],
      filePaths: [
        '~/.claude/settings.json',
        '~/.claude/settings.local.json',
        '~/.claude/CLAUDE.md',
        '~/.claude/mcp.json',
        '~/.claude.json',
        // $CLAUDE_CONFIG_DIR keeps .claude.json inside it (expanded by the probe)
        '${CLAUDE_CONFIG_DIR}/.claude.json',
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        // so findCLIBinary can resolve the binary in remote snapshots where the
        // non-interactive SSH PATH may not include the install dir.
        '~/.local/bin/claude',
        '~/.npm-global/bin/claude',
        '~/.volta/bin/claude',
        '~/.claude/local/claude',
        '~/.bun/bin/claude',
      ],
      globPatterns: [
        '~/.claude/skills/**',
        '~/.claude/plugins/**',
        '~/.claude/agents/**',
        // User-level memory rules (CC-012)
        '~/.claude/rules/**',
        nvmBinaryGlob('claude'),
        ...npmPackageJsonGlobs(NPM_PACKAGE_NAME),
      ],
      commands: [
        { id: 'claude-which', cmd: 'which', args: ['claude'], timeout: 3000 },
        { id: 'claude-version', cmd: 'claude', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.claude',
        '~/.claude/skills',
        '~/.claude/plugins',
        '~/.claude/agents',
        '~/.claude/rules',
      ],
      envPrefixes: ['CLAUDE_', 'ANTHROPIC_'],
      systemPaths: SYSTEM_CLI_PATHS,
      systemDirListings: [],
    };
  },

  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Network', trustLevel: 0 },
        { id: 'mcp', label: 'MCP Transport', trustLevel: 1 },
        { id: 'tool', label: 'Tool Execution', trustLevel: 2 },
        { id: 'host', label: 'Host FS', trustLevel: 3 },
      ],
      components: [
        { id: 'inbound', label: 'Network / Remote MCP', zone: 'net' },
        {
          id: 'mcp-transport',
          label: 'MCP Transport',
          zone: 'mcp',
          guardCheckIds: ['CC-005', 'CC-006'],
        },
        {
          id: 'tools',
          label: 'Tool Permissions',
          zone: 'tool',
          guardCheckIds: ['CC-001', 'CC-002', 'CC-008'],
        },
        {
          id: 'hooks',
          label: 'Hooks (side-channel)',
          zone: 'tool',
          guardCheckIds: ['CC-003', 'CC-010', 'CC-011'],
        },
        {
          id: 'fs',
          label: 'Host Filesystem',
          zone: 'host',
          guardCheckIds: ['CC-004', 'CC-007', 'CC-009', 'CC-012'],
        },
      ],
      edges: [
        { from: 'inbound', to: 'mcp-transport', kind: 'data' },
        { from: 'mcp-transport', to: 'tools', kind: 'control' },
        { from: 'tools', to: 'fs', kind: 'data' },
        { from: 'tools', to: 'hooks', kind: 'control' },
        { from: 'hooks', to: 'fs', kind: 'control', label: 'arbitrary cmd' },
        {
          from: 'inbound',
          to: 'fs',
          label: 'permission bypass',
          triggerCheckIds: ['CC-001', 'CC-002'],
        },
      ],
    };
  },
};
