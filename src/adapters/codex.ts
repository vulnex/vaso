import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { findNvmBinary, nvmBinaryGlob, npmPackageJsonGlobs } from './nvm-binary.js';
import { getUserHomeDirs } from './openclaw.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';

const CODEX_DIR_NAME = '.codex';
const CONFIG_FILES = ['config.toml', 'auth.json'];
const NPM_PACKAGE_NAME = '@openai/codex';

const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/codex',
  '/opt/homebrew/bin/codex',
  '/usr/bin/codex',
];

const USER_CLI_RELATIVE_PATHS = [
  '.local/bin/codex',
  '.npm-global/bin/codex',
  '.volta/bin/codex',
  '.bun/bin/codex',
  '.cargo/bin/codex',
];

/**
 * Walk ~/.codex/sessions/<year>/<month>/<day>/rollout-*.jsonl, pick the
 * lex-latest path (timestamps sort naturally), and parse the most recent
 * `"model":"..."` from its `turn_context` payloads. Returns undefined if
 * no session is reachable (e.g. user has never run codex on this host).
 */
async function findLatestSessionModel(fs: FSProvider, sessionsDir: string): Promise<string | undefined> {
  let dir = sessionsDir;
  // Walk year → month → day, picking the lex-greatest subdir at each level.
  for (let depth = 0; depth < 3; depth++) {
    let entries;
    try {
      entries = await fs.readdirEntries(dir);
    } catch {
      return undefined;
    }
    const subdirs = entries
      .filter(e => e.isDirectory)
      .map(e => e.name)
      .filter(n => /^\d+$/.test(n))
      .sort();
    if (subdirs.length === 0) return undefined;
    dir = `${dir}/${subdirs[subdirs.length - 1]}`;
  }
  let entries;
  try {
    entries = await fs.readdirEntries(dir);
  } catch {
    return undefined;
  }
  const rollouts = entries
    .filter(e => e.isFile && e.name.startsWith('rollout-') && e.name.endsWith('.jsonl'))
    .map(e => e.name)
    .sort();
  if (rollouts.length === 0) return undefined;
  const latestPath = `${dir}/${rollouts[rollouts.length - 1]}`;
  let content;
  try {
    content = await fs.readFile(latestPath);
  } catch {
    return undefined;
  }
  // Last `"model":"..."` wins — sessions can switch models mid-conversation.
  const re = /"model":"([^"]+)"/g;
  let last: string | undefined;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) last = m[1];
  return last;
}

async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  for (const p of SYSTEM_CLI_PATHS) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS) {
    const p = join(home, rel);
    if (await fs.access(p)) return p;
  }
  const nvm = await findNvmBinary(home, fs, 'codex');
  if (nvm) return nvm;
  try {
    const result = fs.execSync('which', ['codex'], { timeout: 3000 }).trim();
    if (result) return result;
  } catch {}
  return undefined;
}

export const codexAdapter: AgentAdapter = {
  agent: 'codex',
  displayName: 'Codex',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const codexDir = join(home, CODEX_DIR_NAME);
      const cliBinary = await findCLIBinary(home, fs);
      const hasCodexDir = await fs.access(codexDir);

      if (!hasCodexDir && !cliBinary) continue;

      const configFiles = [];
      if (hasCodexDir) {
        for (const filename of CONFIG_FILES) {
          const filePath = join(codexDir, filename);
          if (!(await fs.access(filePath))) continue;
          try {
            configFiles.push(await loadConfig(filePath, fs));
          } catch {}
        }
      }

      const version = queryCliVersion(cliBinary, fs)
        ?? (await readPackageVersion(cliBinary, fs, NPM_PACKAGE_NAME));

      installations.push({
        agent: 'codex',
        version,
        installDir: codexDir,
        configFiles,
        models: await this.getModels?.(configFiles, fs),
        user: options?.allUsers ? user : undefined,
        cliBinary,
      });
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const home = new LocalFSProvider().homedir();
    const codexDir = join(home, CODEX_DIR_NAME);
    return CONFIG_FILES.map(f => join(codexDir, f));
  },

  getSkillsDir(_installDir: string): string | undefined {
    return undefined;
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  async getModels(configs: ParsedConfig[], fs?: FSProvider): Promise<ModelRef[]> {
    const main = configs.find(c => c.filePath.endsWith('config.toml'));
    const id = main?.data?.model as string | undefined;
    if (id) {
      const provider = main?.data?.model_provider as string | undefined;
      return [{ id, provider }];
    }
    // No config.toml model — codex falls back to whatever the user picked at
    // runtime, which it persists per turn in ~/.codex/sessions/<y>/<m>/<d>/
    // rollout-*.jsonl as `turn_context.model`. The latest such record is the
    // most recently active model.
    if (!fs) return [];
    const home = fs.homedir();
    const sessionsDir = `${home}/.codex/sessions`;
    const found = await findLatestSessionModel(fs, sessionsDir);
    return found ? [{ id: found, via: 'last session' }] : [];
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'instructions.md'),
      join(installDir, 'AGENTS.md'),
      join(installDir, 'history.jsonl'),
    ];
  },

  getCredentialPaths(installDir: string): string[] {
    return [
      join(installDir, 'auth.json'),
    ];
  },

  getCLICommand(): string {
    return 'codex';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.codex/config.toml',
        '~/.codex/auth.json',
        '~/.codex/instructions.md',
        '~/.codex/AGENTS.md',
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        '~/.local/bin/codex',
        '~/.npm-global/bin/codex',
        '~/.volta/bin/codex',
        '~/.bun/bin/codex',
        '~/.cargo/bin/codex',
      ],
      globPatterns: [
        // Session jsonls record `turn_context.model` per turn, so the latest
        // session reveals the active model when ~/.codex/config.toml has none.
        '~/.codex/sessions/*/*/*/rollout-*.jsonl',
        nvmBinaryGlob('codex'),
        ...npmPackageJsonGlobs(NPM_PACKAGE_NAME),
      ],
      commands: [
        { id: 'codex-which', cmd: 'which', args: ['codex'], timeout: 3000 },
        { id: 'codex-version', cmd: 'codex', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.codex',
        '~/.codex/sessions',
      ],
      envPrefixes: ['CODEX_', 'OPENAI_'],
      systemPaths: SYSTEM_CLI_PATHS,
      systemDirListings: [],
    };
  },

  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Network', trustLevel: 0 },
        { id: 'mcp', label: 'MCP Transport', trustLevel: 1 },
        { id: 'sbx', label: 'Sandbox Mode', trustLevel: 2 },
        { id: 'host', label: 'Host FS', trustLevel: 3 },
      ],
      components: [
        { id: 'inbound', label: 'Network / Remote MCP', zone: 'net' },
        {
          id: 'mcp-transport',
          label: 'MCP Transport',
          zone: 'mcp',
          guardCheckIds: ['CDX-004'],
        },
        {
          id: 'sandbox',
          label: 'Sandbox Mode (read/workspace/danger)',
          zone: 'sbx',
          guardCheckIds: ['CDX-001', 'CDX-002', 'CDX-005', 'CDX-006', 'CDX-008'],
        },
        {
          id: 'fs',
          label: 'Host Filesystem',
          zone: 'host',
          guardCheckIds: ['CDX-003', 'CDX-007', 'CDX-009'],
        },
      ],
      edges: [
        { from: 'inbound', to: 'mcp-transport', kind: 'data' },
        { from: 'mcp-transport', to: 'sandbox', kind: 'control' },
        { from: 'sandbox', to: 'fs', kind: 'data' },
        {
          from: 'inbound',
          to: 'fs',
          label: 'sandbox bypass',
          triggerCheckIds: ['CDX-001', 'CDX-002'],
        },
      ],
    };
  },
};
