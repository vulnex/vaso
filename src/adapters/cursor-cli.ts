import { join, basename } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { findNvmBinary, nvmBinaryGlob } from './nvm-binary.js';
import { getUserHomeDirs } from './openclaw.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';

const CURSOR_DIR_NAME = '.cursor';
const USER_CONFIG_FILES = ['cli-config.json', 'mcp.json'];

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

async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  for (const p of SYSTEM_CLI_PATHS) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS) {
    const p = join(home, rel);
    if (await fs.access(p)) return p;
  }
  const nvm = await findNvmBinary(home, fs, 'cursor-agent');
  if (nvm) return nvm;
  try {
    const result = fs.execSync('which', ['cursor-agent'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}
  return undefined;
}

async function loadFiles(dir: string, names: string[], fs: FSProvider): Promise<ParsedConfig[]> {
  const out: ParsedConfig[] = [];
  for (const name of names) {
    const filePath = join(dir, name);
    if (!(await fs.access(filePath))) continue;
    try {
      out.push(await loadConfig(filePath, fs));
    } catch {}
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
      const cliBinary = await findCLIBinary(home, fs);
      const hasCursorDir = await fs.access(cursorDir);

      if (!hasCursorDir && !cliBinary) continue;

      const configFiles = hasCursorDir ? await loadFiles(cursorDir, USER_CONFIG_FILES, fs) : [];

      // ~/.cursor/ is the Cursor *IDE* config dir (argv.json, extensions/,
      // projects/, ide_state.json). The CLI's signal is `cli-config.json` /
      // `mcp.json` or the `cursor-agent` binary; without either, this is the
      // IDE, not the CLI.
      if (configFiles.length === 0 && !cliBinary) continue;

      const version = queryCliVersion(cliBinary, fs)
        ?? (await readPackageVersion(cliBinary, fs));

      installations.push({
        agent: 'cursor-cli',
        version,
        installDir: cursorDir,
        configFiles,
        models: extractModels(configFiles),
        user: options?.allUsers ? user : undefined,
        cliBinary,
      });
    }

    // Project-level: .cursor/mcp.json under cwd
    const cwd = process.cwd();
    const projectCursorDir = join(cwd, CURSOR_DIR_NAME);
    if (await fs.access(projectCursorDir)) {
      const projectConfigs = await loadFiles(projectCursorDir, ['mcp.json', 'cli.json'], fs);
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
    const home = new LocalFSProvider().homedir();
    const cursorDir = join(home, CURSOR_DIR_NAME);
    return USER_CONFIG_FILES.map(f => join(cursorDir, f));
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
        '~/.cursor/cli-config.json',
        '~/.cursor/mcp.json',
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
        nvmBinaryGlob('cursor-agent'),
      ],
      commands: [
        { id: 'cursor-agent-which', cmd: 'which', args: ['cursor-agent'], timeout: 3000 },
        { id: 'cursor-agent-version', cmd: 'cursor-agent', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.cursor',
        '~/.cursor/rules',
        '~/.cursor/extensions',
      ],
      envPrefixes: ['CURSOR_'],
      systemPaths: SYSTEM_CLI_PATHS,
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
