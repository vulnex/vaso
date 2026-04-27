import { join, basename } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { getUserHomeDirs } from './openclaw.js';
import { queryCliVersion } from './version-query.js';

const CLAUDE_DIR_NAME = '.claude';
const SETTINGS_FILES = ['settings.json', 'settings.local.json'];
const ROOT_STATE_FILE = '.claude.json';

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

async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  for (const p of SYSTEM_CLI_PATHS) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS) {
    const p = join(home, rel);
    if (await fs.access(p)) return p;
  }
  try {
    const result = fs.execSync('which', ['claude'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}
  return undefined;
}

async function loadSettingsFiles(dir: string, fs: FSProvider) {
  const configFiles = [];
  for (const filename of SETTINGS_FILES) {
    const filePath = join(dir, filename);
    if (!(await fs.access(filePath))) continue;
    try {
      configFiles.push(await loadConfig(filePath, fs));
    } catch {}
  }
  return configFiles;
}

export const claudeCodeAdapter: AgentAdapter = {
  agent: 'claude-code',
  displayName: 'Claude Code',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const claudeDir = join(home, CLAUDE_DIR_NAME);
      const rootStateFile = join(home, ROOT_STATE_FILE);

      const cliBinary = await findCLIBinary(home, fs);
      const hasClaudeDir = await fs.access(claudeDir);
      const hasRootState = await fs.access(rootStateFile);

      if (!hasClaudeDir && !hasRootState && !cliBinary) continue;

      const configFiles = hasClaudeDir ? await loadSettingsFiles(claudeDir, fs) : [];

      if (hasRootState) {
        try {
          configFiles.push(await loadConfig(rootStateFile, fs));
        } catch {}
      }

      const version = queryCliVersion(cliBinary, fs);
      const skillsDir = this.getSkillsDir(claudeDir);

      installations.push({
        agent: 'claude-code',
        version,
        installDir: claudeDir,
        configFiles,
        skillsDir,
        user: options?.allUsers ? user : undefined,
        cliBinary,
      });
    }

    // Project-level config in current working directory
    const cwd = process.cwd();
    const projectClaudeDir = join(cwd, CLAUDE_DIR_NAME);
    if (await fs.access(projectClaudeDir)) {
      const projectConfigs = await loadSettingsFiles(projectClaudeDir, fs);
      if (projectConfigs.length > 0) {
        installations.push({
          agent: 'claude-code',
          agentName: `project:${basename(cwd)}`,
          installDir: projectClaudeDir,
          configFiles: projectConfigs,
          skillsDir: this.getSkillsDir(projectClaudeDir),
          profile: 'project',
        });
      }
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    const claudeDir = join(home, CLAUDE_DIR_NAME);
    return [
      ...SETTINGS_FILES.map(f => join(claudeDir, f)),
      join(home, ROOT_STATE_FILE),
    ];
  },

  getSkillsDir(installDir: string): string | undefined {
    return join(installDir, 'skills');
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
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
      filePaths: [
        '~/.claude/settings.json',
        '~/.claude/settings.local.json',
        '~/.claude/CLAUDE.md',
        '~/.claude/.credentials.json',
        '~/.claude.json',
      ],
      globPatterns: [
        '~/.claude/skills/**',
        '~/.claude/plugins/**',
        '~/.claude/agents/**',
      ],
      commands: [
        { id: 'claude-which', cmd: 'which', args: ['claude'], timeout: 3000 },
        { id: 'claude-version', cmd: 'claude', args: ['--version'], timeout: 3000 },
      ],
      directoryListings: [
        '~/.claude',
        '~/.claude/skills',
        '~/.claude/plugins',
        '~/.claude/agents',
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
