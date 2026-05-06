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

async function findCLIBinary(home: string, fs: FSProvider): Promise<string | undefined> {
  for (const p of SYSTEM_CLI_PATHS) {
    if (await fs.access(p)) return p;
  }
  for (const rel of USER_CLI_RELATIVE_PATHS) {
    const p = join(home, rel);
    if (await fs.access(p)) return p;
  }
  const nvm = await findNvmBinary(home, fs, 'gemini');
  if (nvm) return nvm;
  try {
    const result = fs.execSync('which', ['gemini'], { timeout: 3000 }).trim();
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
    const home = fs.homedir();
    const tmpDir = `${home}/.gemini/tmp`;
    const found = await findLatestSessionModel(fs, tmpDir);
    if (found) return [{ id: found, provider: 'google', via: 'last session' }];
  }
  return [];
}

export const geminiAdapter: AgentAdapter = {
  agent: 'gemini-cli',
  displayName: 'Gemini CLI',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const geminiDir = join(home, GEMINI_DIR_NAME);
      const cliBinary = await findCLIBinary(home, fs);
      const hasGeminiDir = await fs.access(geminiDir);

      if (!hasGeminiDir && !cliBinary) continue;

      const configFiles = hasGeminiDir ? await loadSettings(geminiDir, fs) : [];

      // A bare ~/.gemini/ with no recognized config files and no `gemini`
      // binary is leftover state from another tool (Google's IDE extensions
      // and other Gemini-branded tooling all touch this path), not a CLI
      // install.
      if (configFiles.length === 0 && !cliBinary) continue;

      const version = queryCliVersion(cliBinary, fs)
        ?? (await readPackageVersion(cliBinary, fs, NPM_PACKAGE_NAME));

      installations.push({
        agent: 'gemini-cli',
        version,
        installDir: geminiDir,
        configFiles,
        models: await extractModels(configFiles, fs),
        user: options?.allUsers ? user : undefined,
        cliBinary,
      });
    }

    // Project-level config in current working directory (Gemini reads
    // ./.gemini/settings.json when the workspace is trusted).
    const cwd = process.cwd();
    const projectGeminiDir = join(cwd, GEMINI_DIR_NAME);
    if (await fs.access(projectGeminiDir)) {
      const projectConfigs = await loadSettings(projectGeminiDir, fs);
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
    const home = new LocalFSProvider().homedir();
    const geminiDir = join(home, GEMINI_DIR_NAME);
    return [join(geminiDir, SETTINGS_FILE)];
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
      filePaths: [
        '~/.gemini/settings.json',
        '~/.gemini/memory.md',
        '~/.gemini/GEMINI.md',
        '~/.gemini/oauth_creds.json',
        '~/.gemini/google_accounts.json',
        '~/.gemini/mcp-oauth-tokens.json',
        '~/.gemini/a2a-oauth-tokens.json',
        '~/.gemini/installation_id',
        '~/.gemini/trustedFolders.json',
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
        // Session transcripts hold per-message `model` field — the empirical
        // active model when settings.json has no `model.name`.
        '~/.gemini/tmp/*/chats/session-*.jsonl',
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
      systemPaths: SYSTEM_CLI_PATHS,
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
