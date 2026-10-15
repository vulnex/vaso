import { basename, join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfigIfPresent } from './load-if-present.js';
import { nvmBinaryGlob, npmPackageJsonGlobs } from './nvm-binary.js';
import { discoverCliInstalls } from './cli-installs.js';
import { getUserHomeDirs } from './openclaw.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';
import { envPath } from './env-path.js';

const CODEX_DIR_NAME = '.codex';
// auth.json holds OAuth tokens; only its presence and permissions matter
// (CDX-003), so it is never parsed.
const CONFIG_FILES = ['config.toml'];
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

// Codex 0.134+: `codex -p <name>` layers $CODEX_HOME/<name>.config.toml over
// config.toml; the old [profiles.<name>] tables are no longer read
// (learn.chatgpt.com/docs/config-file — "Profiles").
const PROFILE_FILE = /^(.+)\.config\.toml$/;

/** The profile name of a `$CODEX_HOME/<name>.config.toml` file, else undefined. */
export function codexProfileName(filePath: string): string | undefined {
  return PROFILE_FILE.exec(basename(filePath))?.[1];
}

async function loadProfileFiles(codexDir: string, fs: FSProvider): Promise<ParsedConfig[]> {
  let names: string[];
  try {
    names = (await fs.readdir(codexDir)).filter(n => PROFILE_FILE.test(n)).sort();
  } catch {
    return [];
  }
  const out: ParsedConfig[] = [];
  for (const name of names) {
    const loaded = await loadConfigIfPresent(join(codexDir, name), fs);
    if (loaded) out.push(loaded);
  }
  return out;
}

/**
 * Projects the user config marks `trust_level = "trusted"`. Codex loads a
 * project's `.codex/` layer (config.toml, rules/) only for trusted projects
 * (learn.chatgpt.com/docs/config-file — project-scoped config).
 */
function trustedProjects(configs: ParsedConfig[]): string[] {
  const projects = configs.find(c => basename(c.filePath) === 'config.toml')?.data?.projects;
  if (!projects || typeof projects !== 'object') return [];
  return Object.entries(projects as Record<string, unknown>)
    .filter(([, p]) => (p as Record<string, unknown> | null)?.trust_level === 'trusted')
    .map(([path]) => path);
}

/**
 * ~/.codex, or $CODEX_HOME for the scanning user (Codex keeps config, auth,
 * rules, AGENTS.md and sessions there). Another user's environment isn't
 * observable, so --all-users homes use the default.
 */
export function codexHome(home: string, fs: FSProvider): string {
  return envPath(home === fs.homedir() ? fs.getEnv?.('CODEX_HOME') : undefined, home) ?? join(home, CODEX_DIR_NAME);
}

/**
 * Skill roots Codex loads (developers.openai.com Codex "Agent skills"):
 * $CODEX_HOME/skills, the cross-agent user dir ~/.agents/skills, and the
 * administrator dir /etc/codex/skills. Only existing ones are listed.
 */
async function codexSkillDirs(home: string, codexDir: string, fs: FSProvider): Promise<Pick<AgentInstallation, 'skillsDir' | 'skillsDirs'>> {
  const candidates = [join(codexDir, 'skills'), join(home, '.agents', 'skills')];
  if (home === fs.homedir()) candidates.push('/etc/codex/skills');
  const dirs: string[] = [];
  for (const d of candidates) if (await fs.access(d)) dirs.push(d);
  return dirs.length > 0 ? { skillsDir: dirs[0], ...(dirs.length > 1 ? { skillsDirs: dirs } : {}) } : {};
}

export const codexAdapter: AgentAdapter = {
  agent: 'codex',
  displayName: 'Codex',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const codexDir = codexHome(home, fs);
      const installs = await discoverCliInstalls(home, fs, {
        names: ['codex'],
        systemPaths: SYSTEM_CLI_PATHS,
        userRelPaths: USER_CLI_RELATIVE_PATHS,
        version: async (bin, canExec) => (canExec ? queryCliVersion(bin, fs) : undefined)
          ?? (await readPackageVersion(bin, fs, NPM_PACKAGE_NAME)),
      });
      const cliBinary = installs.primary?.path;
      const hasCodexDir = await fs.access(codexDir);

      if (!hasCodexDir && !cliBinary) continue;

      const configFiles = [];
      if (hasCodexDir) {
        for (const filename of CONFIG_FILES) {
          const filePath = join(codexDir, filename);
          const loaded = await loadConfigIfPresent(filePath, fs);
          if (loaded) configFiles.push(loaded);
        }
        configFiles.push(...await loadProfileFiles(codexDir, fs));
      }

      // A bare ~/.codex/ with no config, no sign-in and no `codex` binary is
      // leftover state, not a CLI install.
      const signedIn = hasCodexDir && (await fs.access(join(codexDir, 'auth.json')));
      if (configFiles.length === 0 && !signedIn && !cliBinary) continue;

      const version = installs.primary?.version;

      installations.push({
        agent: 'codex',
        version,
        installDir: codexDir,
        configFiles,
        ...(await codexSkillDirs(home, codexDir, fs)),
        models: await this.getModels?.(configFiles, fs),
        user: options?.allUsers ? user : undefined,
        cliBinary,
        otherInstalls: installs.others.length > 0 ? installs.others : undefined,
      });

      // Trusted projects' `.codex/` layers: the project config and its rules
      for (const project of trustedProjects(configFiles)) {
        if (!project.startsWith('/')) continue;
        const projectDir = join(project, CODEX_DIR_NAME);
        if (projectDir === codexDir || installations.some(i => i.installDir === projectDir)) continue;
        if (!(await fs.access(projectDir))) continue;
        const projectConfig = await loadConfigIfPresent(join(projectDir, 'config.toml'), fs);
        const hasRules = await fs.access(join(projectDir, 'rules'));
        if (!projectConfig && !hasRules) continue;
        installations.push({
          agent: 'codex',
          agentName: `project:${basename(project)}`,
          version,
          installDir: projectDir,
          configFiles: projectConfig ? [projectConfig] : [],
          user: options?.allUsers ? user : undefined,
          profile: 'project',
        });
      }
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    const codexDir = codexHome(fs.homedir(), fs);
    return CONFIG_FILES.map(f => join(codexDir, f));
  },

  getSkillsDir(installDir: string): string | undefined {
    // $CODEX_HOME/skills/<name>/SKILL.md (often links into a tool's checkout)
    return join(installDir, 'skills');
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  async getModels(configs: ParsedConfig[], fs?: FSProvider): Promise<ModelRef[]> {
    const main = configs.find(c => basename(c.filePath) === 'config.toml');
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
    const sessionsDir = join(codexHome(fs.homedir(), fs), 'sessions');
    const found = await findLatestSessionModel(fs, sessionsDir);
    return found ? [{ id: found, via: 'last session' }] : [];
  },

  getMemoryFiles(installDir: string): string[] {
    return [
      join(installDir, 'instructions.md'),
      join(installDir, 'AGENTS.md'),
      join(installDir, 'AGENTS.override.md'),
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
        '~/.codex/instructions.md',
        '~/.codex/AGENTS.md',
        // Replaces AGENTS.md at the global scope when present (CDX-007)
        '~/.codex/AGENTS.override.md',
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        '~/.local/bin/codex',
        '~/.npm-global/bin/codex',
        '~/.volta/bin/codex',
        '~/.bun/bin/codex',
        '~/.cargo/bin/codex',
      ],
      globPatterns: [
        // Prefix allow rules (CDX-010)
        '~/.codex/rules/*.rules',
        // Profile files, `codex -p <name>` (CDX-008/009)
        '~/.codex/*.config.toml',
        // User skills (SKL/IOC checks; skill links are followed by the probe)
        '~/.codex/skills/**',
        // Cross-agent user skills and the administrator skills dir
        '~/.agents/skills/**',
        '/etc/codex/skills/**',
        nvmBinaryGlob('codex'),
        ...npmPackageJsonGlobs(NPM_PACKAGE_NAME),
      ],
      // Session transcripts are private; remotely only their presence is
      // recorded (the last-session model hint is local-scan only).
      metadataGlobPatterns: [
        // OAuth token store — permissions only (CDX-003), never content
        '~/.codex/auth.json',
        '~/.codex/sessions/*/*/*/rollout-*.jsonl',
      ],
      commands: [
        { id: 'codex-which', cmd: 'which', args: ['codex'], timeout: 3000 },
        { id: 'codex-version', cmd: 'codex', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.codex',
        '~/.codex/sessions',
        '~/.codex/skills',
        '~/.agents/skills',
        '/etc/codex/skills',
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
