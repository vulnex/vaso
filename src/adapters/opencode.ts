import { basename, dirname, join } from 'node:path';
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
import { loadConfigIfPresent } from './load-if-present.js';
import { withoutLoadedConfigs, scanCwd, isLoadedInstallDir } from './project-configs.js';
import { xdgPath } from './env-path.js';

const SYSTEM_CLI_PATHS = [
  '/usr/local/bin/opencode',
  '/opt/homebrew/bin/opencode',
  '/usr/bin/opencode',
];

const USER_CLI_RELATIVE_PATHS = [
  '.opencode/bin/opencode',
  '.local/bin/opencode',
  '.bun/bin/opencode',
  '.npm-global/bin/opencode',
];

// OpenCode follows the XDG Base Directory spec. Files we care about:
//   $XDG_CONFIG_HOME/opencode/opencode.json[c]   — primary config
//   $XDG_DATA_HOME/opencode/auth.json            — credentials (0600)
//   $XDG_DATA_HOME/opencode/AGENTS.md            — global memory file
export function xdgConfigDir(home: string, fs: FSProvider): string {
  const xdg = xdgPath(fs.getEnv('XDG_CONFIG_HOME'));
  return xdg ? join(xdg, 'opencode') : join(home, '.config', 'opencode');
}

export function xdgDataDir(home: string, fs: FSProvider): string {
  const xdg = xdgPath(fs.getEnv('XDG_DATA_HOME'));
  return xdg ? join(xdg, 'opencode') : join(home, '.local', 'share', 'opencode');
}

// In OpenCode's merge order — a later file wins (OpenCode 1.19 config.ts):
// the global dir merges config.json, opencode.json, then opencode.jsonc;
// project dirs (ConfigPaths.files) and $OPENCODE_CONFIG_DIR merge
// opencode.json then opencode.jsonc
const CONFIG_FILENAMES = ['opencode.json', 'opencode.jsonc'];
const GLOBAL_CONFIG_FILENAMES = ['config.json', ...CONFIG_FILENAMES];

async function loadOpenCodeConfig(filePath: string, fs: FSProvider): Promise<ParsedConfig | undefined> {
  // The shared loader parses JSON, JSONC and JSON5 and reports an unreadable
  // or unparseable file as CONFIG-LOAD instead of dropping the agent silently
  return loadConfigIfPresent(filePath, fs);
}

async function loadConfigsIn(dir: string, fs: FSProvider, names = CONFIG_FILENAMES): Promise<ParsedConfig[]> {
  const out: ParsedConfig[] = [];
  for (const name of names) {
    const filePath = join(dir, name);
    const parsed = await loadOpenCodeConfig(filePath, fs);
    if (parsed) out.push(parsed);
  }
  return out;
}

/** JSON held in an environment variable, as a config layer named after it. */
function envConfig(name: string, fs: FSProvider, wrap?: (v: unknown) => Record<string, unknown>): ParsedConfig | undefined {
  const raw = fs.getEnv(name)?.trim();
  if (!raw) return undefined;
  try {
    const value = JSON.parse(stripJsonc(raw)) as unknown;
    const data = wrap ? wrap(value) : value;
    if (!data || typeof data !== 'object' || Array.isArray(data)) return undefined;
    return { raw, format: 'json', filePath: `$${name}`, data: data as Record<string, unknown> };
  } catch {
    return undefined;
  }
}

/**
 * Project root and config dirs: OpenCode "looks for a config file in the
 * current directory, then traverses up to the nearest Git directory"
 * (opencode.ai/docs/config). Outside a git repo only the cwd counts.
 */
async function projectDirs(cwd: string, fs: FSProvider): Promise<{ root: string; dirs: string[] }> {
  const dirs: string[] = [];
  for (let dir = cwd; ; dir = dirname(dir)) {
    dirs.push(dir);
    if (await fs.access(join(dir, '.git'))) return { root: dir, dirs };
    if (dirname(dir) === dir) return { root: cwd, dirs: [cwd] };
  }
}

function splitProviderModel(spec: string): { id: string; provider?: string } {
  const idx = spec.indexOf('/');
  if (idx === -1) return { id: spec };
  return { provider: spec.slice(0, idx), id: spec.slice(idx + 1) };
}

const PROJECT_CONTENT_DIRS = ['agent', 'agents', 'command', 'commands', 'plugin', 'plugins', 'mode', 'modes', 'tool', 'tools'];

async function hasProjectContent(dir: string, fs: FSProvider): Promise<boolean> {
  for (const sub of PROJECT_CONTENT_DIRS) {
    if (await fs.access(join(dir, sub))) return true;
  }
  return false;
}

export const opencodeAdapter: AgentAdapter = {
  agent: 'opencode',
  displayName: 'OpenCode',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    for (const { home, user } of userDirs) {
      const configDir = xdgConfigDir(home, fs);
      const dataDir = xdgDataDir(home, fs);
      const installs = await discoverCliInstalls(home, fs, {
        names: ['opencode'],
        systemPaths: SYSTEM_CLI_PATHS,
        userRelPaths: USER_CLI_RELATIVE_PATHS,
        version: async (bin, canExec) => (canExec ? queryCliVersion(bin, fs) : undefined)
          ?? (await readPackageVersion(bin, fs, 'opencode-ai')),
      });
      const cliBinary = installs.primary?.path;

      const configFiles: ParsedConfig[] = await loadConfigsIn(configDir, fs, GLOBAL_CONFIG_FILENAMES);
      // Environment layers (the scanning user's environment only), in
      // OpenCode's merge order: $OPENCODE_CONFIG (an extra file),
      // $OPENCODE_CONFIG_DIR (an extra config dir: opencode.json, agents,
      // plugins), $OPENCODE_CONFIG_CONTENT (inline JSON) and
      // $OPENCODE_PERMISSION (inline permission JSON)
      const self = home === fs.homedir();
      const extra = self ? fs.getEnv('OPENCODE_CONFIG')?.trim() : undefined;
      if (extra && !configFiles.some(c => c.filePath === extra) && await fs.access(extra)) {
        const parsed = await loadOpenCodeConfig(extra, fs);
        if (parsed) configFiles.push(parsed);
      }
      const extraDir = self ? fs.getEnv('OPENCODE_CONFIG_DIR')?.trim() : undefined;
      if (extraDir && extraDir !== configDir) {
        configFiles.push(...await loadConfigsIn(extraDir, fs));
      }
      if (self) {
        const content = envConfig('OPENCODE_CONFIG_CONTENT', fs);
        const permission = envConfig('OPENCODE_PERMISSION', fs, v => ({ permission: v }));
        configFiles.push(...[content, permission].filter((c): c is ParsedConfig => c !== undefined));
      }

      const authPath = join(dataDir, 'auth.json');
      const hasAuth = await fs.access(authPath);

      // Require at least one positive signal — recognized config, auth file,
      // or CLI binary. (`findCLIBinary` already covers ~/.opencode/bin/opencode,
      // so a bare ~/.opencode/ dir alone isn't a useful signal — it would
      // false-positive against unrelated tools sharing the directory name.)
      if (configFiles.length === 0 && !hasAuth && !cliBinary) continue;

      const version = installs.primary?.version;

      installations.push({
        agent: 'opencode',
        version,
        installDir: configDir,
        configFiles,
        models: await this.getModels?.(configFiles),
        user: options?.allUsers ? user : undefined,
        cliBinary,
        otherInstalls: installs.others.length > 0 ? installs.others : undefined,
      });
    }

    // Project config: opencode.json[c] from the cwd up to the git root, plus
    // the project's .opencode/ dir (agents, plugins). installDir is that
    // .opencode/ dir so per-agent markdown under it is found (OPC-006).
    const cwd = scanCwd(fs);
    if (!cwd) return installations;
    const { root, dirs } = await projectDirs(cwd, fs);
    const projectConfigs: ParsedConfig[] = [];
    // Outermost first — the config nearest the cwd wins the merge
    for (const dir of [...dirs].reverse()) projectConfigs.push(...await loadConfigsIn(dir, fs));
    const projectDir = join(root, '.opencode');
    const fresh = await withoutLoadedConfigs(projectConfigs, installations, fs);
    const isUserDir = await isLoadedInstallDir(projectDir, installations, fs);
    // A .opencode/ dir is a project only with configs or project content
    // (agents, commands, plugins, modes): ~/.opencode is also the official
    // installer's dir (bin/, node_modules), which scanning from $HOME reached
    if (!isUserDir && (fresh.length > 0 || await hasProjectContent(projectDir, fs))) {
      installations.push({
        agent: 'opencode',
        agentName: `project:${basename(root)}`,
        version: installations[0]?.version,
        installDir: projectDir,
        configFiles: fresh,
        models: await this.getModels?.(fresh),
        profile: 'project',
      });
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    const home = fs.homedir();
    const configDir = xdgConfigDir(home, fs);
    return GLOBAL_CONFIG_FILENAMES.map(f => join(configDir, f));
  },

  getSkillsDir(_installDir: string): string | undefined {
    // OpenCode skills are addressed via config.skills (paths/URLs), not a fixed
    // directory like Claude Code. Generic skill-dir scans don't apply.
    return undefined;
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    const refs: ModelRef[] = [];
    for (const c of configs) {
      const model = c.data.model;
      if (typeof model === 'string' && model.length > 0) {
        refs.push(splitProviderModel(model));
      }
      const small = c.data.small_model;
      if (typeof small === 'string' && small.length > 0) {
        refs.push({ ...splitProviderModel(small), via: 'small_model' });
      }
    }
    return refs;
  },

  getMemoryFiles(installDir: string): string[] {
    // installDir == XDG config dir; AGENTS.md lives next to opencode.json
    return [
      join(installDir, 'AGENTS.md'),
      join(installDir, 'CLAUDE.md'),
    ];
  },

  getCredentialPaths(_installDir: string, scanFs?: FSProvider): string[] {
    // installDir is the XDG config dir; auth.json lives in the data dir, which
    // we resolve from the scanned host's $HOME (XDG-aware). Cross-user `--all-users`
    // resolution would need the per-user home, but that's not a use case OpenCode
    // currently supports — it's user-installed only.
    const fs = scanFs ?? new LocalFSProvider();
    const home = fs.homedir();
    return [join(xdgDataDir(home, fs), 'auth.json')];
  },

  getCLICommand(): string {
    return 'opencode';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        // extra config file named by $OPENCODE_CONFIG (expanded by the probe)
        '${OPENCODE_CONFIG}',
        '~/.config/opencode/config.json',
        '~/.config/opencode/opencode.json',
        '~/.config/opencode/opencode.jsonc',
        '~/.config/opencode/AGENTS.md',
        '~/.config/opencode/CLAUDE.md',
        // User-relative CLI install locations — kept in sync with USER_CLI_RELATIVE_PATHS
        '~/.opencode/bin/opencode',
        '~/.local/bin/opencode',
        '~/.bun/bin/opencode',
        '~/.npm-global/bin/opencode',
      ],
      // Provider token store — existence and permissions only, never content
      metadataGlobPatterns: [
        '~/.local/share/opencode/auth.json',
      ],
      globPatterns: [
        // package.json of every npm-global copy — versions non-primary copies on remote scans
        ...npmPackageJsonGlobs('opencode-ai'),
        '~/.config/opencode/agent/*.md',
        '~/.config/opencode/agents/*.md',
        // $OPENCODE_CONFIG_DIR config + agents (expanded by the probe)
        '${OPENCODE_CONFIG_DIR}/opencode.json',
        '${OPENCODE_CONFIG_DIR}/opencode.jsonc',
        '${OPENCODE_CONFIG_DIR}/agent/*.md',
        '${OPENCODE_CONFIG_DIR}/agents/*.md',
        '~/.config/opencode/plugin/*.{ts,js}',
        '~/.config/opencode/plugins/*.{ts,js}',
        nvmBinaryGlob('opencode'),
      ],
      commands: [
        { id: 'opencode-which', cmd: 'which', args: ['opencode'], timeout: 3000 },
        { id: 'opencode-version', cmd: 'opencode', args: ['--version'], timeout: 15000 },
      ],
      directoryListings: [
        '~/.config/opencode',
        '~/.local/share/opencode',
        '~/.opencode/bin',
      ],
      envPrefixes: ['OPENCODE_', 'XDG_'],
      systemPaths: SYSTEM_CLI_PATHS,
      systemDirListings: [],
    };
  },

  // OpenCode's privilege gradient runs through three gates: the permission
  // layer (ask/allow/deny on bash/edit/etc.), the MCP transport, and the plugin
  // loader. Failures in any of those let untrusted input reach the host FS.
  // Inversion edges fire when sharing is auto-enabled or when permissions are
  // globally allowed — both bypass the intended gate.
  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Network / Cloud Sync', trustLevel: 0 },
        { id: 'ext', label: 'MCP + Plugins', trustLevel: 1 },
        { id: 'perm', label: 'Permission Layer', trustLevel: 2 },
        { id: 'host', label: 'Host Filesystem', trustLevel: 3 },
      ],
      components: [
        {
          id: 'inbound',
          label: 'Network / Cloud Sync',
          zone: 'net',
          guardCheckIds: ['OPC-004', 'OPC-009'],
        },
        {
          id: 'mcp-plugins',
          label: 'MCP Servers + Plugins',
          zone: 'ext',
          guardCheckIds: ['OPC-003', 'OPC-005', 'OPC-010'],
        },
        {
          id: 'permission',
          label: 'Permission Layer',
          zone: 'perm',
          guardCheckIds: ['OPC-002', 'OPC-006', 'OPC-008'],
        },
        {
          id: 'fs',
          label: 'Host Filesystem',
          zone: 'host',
          guardCheckIds: ['OPC-001', 'OPC-007'],
        },
      ],
      edges: [
        { from: 'inbound', to: 'mcp-plugins', kind: 'data' },
        { from: 'mcp-plugins', to: 'permission', kind: 'control' },
        { from: 'permission', to: 'fs', kind: 'data' },
        {
          from: 'inbound',
          to: 'fs',
          label: 'permission bypass',
          triggerCheckIds: ['OPC-002', 'OPC-008'],
        },
      ],
    };
  },
};
