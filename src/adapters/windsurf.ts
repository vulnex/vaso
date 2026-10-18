import { dirname, join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfigIfPresent, pathPresent } from './load-if-present.js';
import { recordConfigLoadFailure } from '../core/config-loader.js';
import { getUserHomeDirs } from './openclaw.js';
import { queryCliVersion } from './version-query.js';
import { decodeWindsurfUserSettings, toWindsurfSettingsData } from './windsurf-user-settings.js';
import { devinCliPresent, projectDirs } from './devin.js';
import { scanCwd, withoutLoadedConfigs } from './project-configs.js';
import { linuxConfigHome } from './env-path.js';

// Windsurf IDE was rebranded Devin Desktop on 2026-06-02. One adapter covers
// both generations: legacy installs keep the Windsurf app bundle / user-data
// dirs and the ~/.codeium/windsurf agent data dir; new installs use Devin
// naming plus an XDG-style ~/.config/devin dir for the MCP config.

const APP_BUNDLES = ['/Applications/Windsurf.app', '/Applications/Devin.app'];
const CLI_NAMES = ['windsurf', 'devin-desktop'];
const EDITOR_DIR_NAMES = ['Windsurf', 'Devin'];
const MCP_CONFIG_FILE = 'mcp_config.json';
// 3.x: Cascade execution-gate settings (protobuf) — see windsurf-user-settings.ts
const USER_SETTINGS_FILE = 'user_settings.pb';
// 3.x: Devin agent config shared with Devin CLI (`permissions` allow/deny/ask)
const DEVIN_CONFIG_FILE = 'config.json';
// Cascade skills (<name>/SKILL.md beneath each root; docs.devin.ai/desktop/cascade/skills).
// User: ~/.codeium/windsurf/skills, plus ~/.config/devin/skills and
// ~/.agents/skills, which Devin CLI reads too. Workspace: .devin/skills and
// .agents/skills (the devin adapter's project install scans those) and the
// legacy .windsurf/skills, which only Devin Desktop reads.
const OWN_USER_SKILL_DIRS = [join('.codeium', 'windsurf', 'skills')];
const SHARED_USER_SKILL_DIRS = [join('.agents', 'skills')];
const LEGACY_PROJECT_SKILL_DIR = join('.windsurf', 'skills');
const HOOKS_FILE = 'hooks.json';
/** Workspace Cascade hooks; the legacy file counts only when the first is absent or defines none. */
const PROJECT_HOOKS_FILES = [join('.devin', HOOKS_FILE), join('.windsurf', HOOKS_FILE)];
/** System-level Cascade hooks per OS — Devin path first, legacy Windsurf path as its fallback. */
const SYSTEM_HOOKS_FILES: Record<'darwin' | 'linux', string[]> = {
  darwin: ['/Library/Application Support/Devin/hooks.json', '/Library/Application Support/Windsurf/hooks.json'],
  linux: ['/etc/devin/hooks.json', '/etc/windsurf/hooks.json'],
};

const SYSTEM_CLI_PATHS = CLI_NAMES.flatMap(name => [
  `/usr/local/bin/${name}`,
  `/opt/homebrew/bin/${name}`,
  `/usr/bin/${name}`,
]);

/** ~/.codeium/windsurf — the Cascade agent data dir (MCP config, memories, workflows). */
function codeiumAgentDir(home: string): string {
  return join(home, '.codeium', 'windsurf');
}

/** XDG-aware config dir for the Devin generation's mcp_config.json. */
function devinConfigDir(home: string, fs: FSProvider): string {
  if (fs.platform === 'win32') {
    const appData = fs.getEnv('APPDATA');
    return join(appData ?? join(home, 'AppData', 'Roaming'), 'devin');
  }
  const xdg = fs.getEnv('XDG_CONFIG_HOME')?.trim();
  return xdg ? join(xdg, 'devin') : join(home, '.config', 'devin');
}

/**
 * Per-user editor user-data dirs (VS Code-style), both generations.
 * macOS: ~/Library/Application Support/{Windsurf,Devin}
 * Windows: %APPDATA%\{Windsurf,Devin}
 * Linux: $XDG_CONFIG_HOME/{Windsurf,Devin} (default ~/.config)
 */
export function editorUserDataDirs(home: string, fs: FSProvider): string[] {
  if (fs.platform === 'darwin') {
    return EDITOR_DIR_NAMES.map(n => join(home, 'Library', 'Application Support', n));
  }
  if (fs.platform === 'win32') {
    const appData = fs.getEnv('APPDATA') ?? join(home, 'AppData', 'Roaming');
    return EDITOR_DIR_NAMES.map(n => join(appData, n));
  }
  return EDITOR_DIR_NAMES.map(n => join(linuxConfigHome(home, fs), n));
}

/**
 * Linux/Windows install roots (the dir holding `resources/app/product.json`).
 * Linux: .deb/.rpm installs under /usr/share or /opt, or the release tarball
 * extracted anywhere — commonly the home dir (`~/devin-desktop`, `~/Windsurf`).
 * Windows: the per-user installer's %LOCALAPPDATA%\Programs\<name>.
 */
const LINUX_SYSTEM_ROOTS = [
  '/usr/share/windsurf', '/usr/share/devin-desktop',
  '/opt/windsurf', '/opt/Windsurf', '/opt/devin-desktop', '/opt/Devin',
];
const HOME_ROOT_NAMES = ['devin-desktop', 'Devin', 'windsurf', 'Windsurf'];

function installRootCandidates(home: string, fs: FSProvider): string[] {
  if (fs.platform === 'win32') {
    const localAppData = fs.getEnv('LOCALAPPDATA') ?? join(home, 'AppData', 'Local');
    return ['Windsurf', 'Devin', 'devin-desktop'].map(n => join(localAppData, 'Programs', n));
  }
  return [
    ...LINUX_SYSTEM_ROOTS,
    ...HOME_ROOT_NAMES.map(n => join(home, n)),
    ...HOME_ROOT_NAMES.map(n => join(home, '.local', 'share', n)),
    ...HOME_ROOT_NAMES.map(n => join(home, 'Applications', n)),
  ];
}

/**
 * The CLI launcher lives at `<root>/bin/<name>` (symlinked from /usr/bin on
 * package installs) or is the main binary at `<root>/<name>`.
 */
async function rootsFromCliBinary(cliBinary: string | undefined, fs: FSProvider): Promise<string[]> {
  if (!cliBinary) return [];
  try {
    const real = await fs.realpath(cliBinary);
    return [dirname(dirname(real)), dirname(real)];
  } catch {
    return [];
  }
}

function systemHooksFiles(fs: FSProvider): string[] {
  if (fs.platform === 'win32') {
    const programData = fs.getEnv('PROGRAMDATA') ?? 'C:\\ProgramData';
    return ['Devin', 'Windsurf'].map(n => join(programData, n, HOOKS_FILE));
  }
  return fs.platform === 'darwin' ? SYSTEM_HOOKS_FILES.darwin : SYSTEM_HOOKS_FILES.linux;
}

function definesHooks(config: ParsedConfig): boolean {
  const hooks = config.data.hooks;
  return !!hooks && typeof hooks === 'object' && Object.values(hooks as Record<string, unknown>)
    .some(v => Array.isArray(v) ? v.length > 0 : !!v);
}

/**
 * The first hooks file of `paths` that exists and defines hooks — Cascade's
 * fallback rule for the system and workspace levels (docs.devin.ai Cascade
 * hooks). A present-but-empty primary still loads (and a broken one still
 * reports CONFIG-LOAD) without hiding the fallback.
 */
async function loadHooksWithFallback(paths: string[], fs: FSProvider): Promise<ParsedConfig[]> {
  const out: ParsedConfig[] = [];
  for (const p of paths) {
    const parsed = await loadConfigIfPresent(p, fs);
    if (!parsed) continue;
    out.push(parsed);
    if (definesHooks(parsed)) break;
  }
  return out;
}

async function findAppBundle(fs: FSProvider): Promise<string | undefined> {
  if (fs.platform !== 'darwin') return undefined;
  for (const bundle of APP_BUNDLES) {
    if (await fs.access(bundle)) return bundle;
  }
  return undefined;
}

interface ProductInfo {
  version?: string;
  applicationName?: string;
}

/**
 * Parse product.json — <app>/Contents/Resources/app/ on macOS,
 * <root>/resources/app/ on Linux/Windows. `applicationName` is
 * "windsurf" (legacy) or "devin-desktop" (new). The build version lives in
 * `windsurfVersion` (e.g. 1.9566.11); `productVersion` is the newer key and
 * plain `version` is the underlying VS Code version — try in that order.
 */
async function readProductInfo(productPath: string, fs: FSProvider): Promise<ProductInfo> {
  try {
    const data = JSON.parse(await fs.readFile(productPath)) as Record<string, unknown>;
    const version = [data.windsurfVersion, data.productVersion, data.version]
      .find((v): v is string => typeof v === 'string' && v.length > 0);
    const applicationName = typeof data.applicationName === 'string' ? data.applicationName : undefined;
    return { version, applicationName };
  } catch {
    return {};
  }
}

async function findCLIBinary(fs: FSProvider): Promise<string | undefined> {
  for (const p of SYSTEM_CLI_PATHS) {
    if (await fs.access(p)) return p;
  }
  for (const name of CLI_NAMES) {
    try {
      const result = fs.execSync('which', [name], { timeout: 3000 }).trim();
      if (result) return result;
    } catch {}
  }
  return undefined;
}

/**
 * Windsurf / Devin Desktop footprint for a user: the Cascade agent dir, an
 * editor user-data dir, or the macOS app bundle. The devin adapter uses it to
 * leave a CLI-less ~/.config/devin to this adapter.
 */
export async function windsurfPresent(home: string, fs: FSProvider): Promise<boolean> {
  if (await fs.access(codeiumAgentDir(home))) return true;
  for (const dir of editorUserDataDirs(home, fs)) {
    if (await fs.access(dir)) return true;
  }
  return (await findAppBundle(fs)) !== undefined;
}

/**
 * 3.x execution-gate settings (protobuf), projected onto windsurf.* keys. An
 * unreadable file or bytes that aren't a protobuf message become CONFIG-LOAD
 * (the execution gate couldn't be judged), as a broken JSON config does.
 */
async function loadUserSettings(filePath: string, fs: FSProvider): Promise<ParsedConfig | undefined> {
  if (!(await pathPresent(filePath, fs))) return undefined;
  let bytes: Uint8Array;
  try {
    bytes = await fs.readBytes(filePath);
  } catch (err) {
    recordConfigLoadFailure(filePath, 'read', err);
    return undefined;
  }
  const decoded = decodeWindsurfUserSettings(bytes);
  if (!decoded) {
    recordConfigLoadFailure(filePath, 'parse', new Error('Content is not a well-formed protobuf message'));
    return undefined;
  }
  return { raw: '', format: 'unknown', filePath, data: toWindsurfSettingsData(decoded) };
}

export const windsurfAdapter: AgentAdapter = {
  agent: 'windsurf',
  displayName: 'Windsurf / Devin Desktop',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    const appBundle = await findAppBundle(fs);
    const macProduct: ProductInfo = appBundle
      ? await readProductInfo(join(appBundle, 'Contents', 'Resources', 'app', 'product.json'), fs)
      : {};
    const cliBinary = await findCLIBinary(fs);
    const cliRoots = appBundle ? [] : await rootsFromCliBinary(cliBinary, fs);

    for (const { home, user } of userDirs) {
      const agentDir = codeiumAgentDir(home);
      const hasAgentDir = await fs.access(agentDir);

      // Linux/Windows: first install root with a readable product.json.
      let installRoot: string | undefined;
      let product = macProduct;
      if (!appBundle) {
        for (const root of [...cliRoots, ...installRootCandidates(home, fs)]) {
          const productPath = join(root, 'resources', 'app', 'product.json');
          if (!(await fs.access(productPath))) continue;
          const info = await readProductInfo(productPath, fs);
          if (!info.applicationName && !info.version) continue;
          installRoot = root;
          product = info;
          break;
        }
      }

      const existingUserDataDirs: string[] = [];
      for (const dir of editorUserDataDirs(home, fs)) {
        if (await fs.access(dir)) existingUserDataDirs.push(dir);
      }

      // Any positive signal → installed.
      if (!hasAgentDir && existingUserDataDirs.length === 0 && !appBundle && !installRoot && !cliBinary) continue;

      const configFiles: ParsedConfig[] = [];
      // ~/.config/devin/{mcp_config,config}.json are shared with Devin CLI;
      // when the CLI is installed its install reports them, not this one.
      const sharedWithDevin = await devinCliPresent(home, fs);

      // MCP configs (both generations).
      const mcpConfigPaths = [
        join(agentDir, MCP_CONFIG_FILE),
        ...(sharedWithDevin ? [] : [join(devinConfigDir(home, fs), MCP_CONFIG_FILE)]),
      ];
      for (const filePath of mcpConfigPaths) {
        const loaded = await loadConfigIfPresent(filePath, fs);
        if (loaded) configFiles.push(loaded);
      }

      // 3.x execution-gate settings, projected onto windsurf.* keys.
      const userHooks = await loadConfigIfPresent(join(agentDir, HOOKS_FILE), fs);
      if (userHooks) configFiles.push(userHooks);

      const userSettings = await loadUserSettings(join(agentDir, USER_SETTINGS_FILE), fs);
      if (userSettings) configFiles.push(userSettings);

      // 3.x Devin agent config (permission rules), shared with Devin CLI.
      if (!sharedWithDevin) {
        const parsed = await loadConfigIfPresent(join(devinConfigDir(home, fs), DEVIN_CONFIG_FILE), fs);
        if (parsed) configFiles.push(parsed);
      }

      // Editor settings (windsurf.* keys; VS Code-flavored JSON, comments and
      // trailing commas tolerated by the shared loader).
      for (const dir of existingUserDataDirs) {
        const parsed = await loadConfigIfPresent(join(dir, 'User', 'settings.json'), fs);
        if (parsed) configFiles.push(parsed);
      }

      const version = product.version
        ?? queryCliVersion(cliBinary, fs, { timeoutMs: 3000 });

      // Skill roots shared with Devin CLI are its install's when the CLI is there
      const skillRoots = [
        ...OWN_USER_SKILL_DIRS.map(rel => join(home, rel)),
        ...(sharedWithDevin ? [] : [
          join(devinConfigDir(home, fs), 'skills'),
          ...SHARED_USER_SKILL_DIRS.map(rel => join(home, rel)),
        ]),
      ];
      const skillsDirs: string[] = [];
      for (const dir of skillRoots) {
        if (await fs.access(dir)) skillsDirs.push(dir);
      }

      const isDevinGeneration = product.applicationName === 'devin-desktop'
        || appBundle === '/Applications/Devin.app';
      // Only the resolved app location is reported; cliBinary stays separate.
      const resolvedAppBundle = appBundle ?? installRoot;

      installations.push({
        agent: 'windsurf',
        agentName: isDevinGeneration ? 'Devin Desktop' : undefined,
        version,
        installDir: hasAgentDir ? agentDir : (existingUserDataDirs[0] ?? agentDir),
        configFiles,
        skillsDir: skillsDirs[0],
        skillsDirs: skillsDirs.length > 0 ? skillsDirs : undefined,
        user: options?.allUsers ? user : undefined,
        appBundle: resolvedAppBundle,
        cliBinary,
      });
    }

    // Workspace .windsurf/skills (repo root down to cwd, as Devin finds .devin/)
    // belong to the scanning user's install
    // System hooks are host-wide: reported once, on the first installation
    if (installations.length > 0) {
      installations[0].configFiles.push(...await loadHooksWithFallback(systemHooksFiles(fs), fs));
    }

    const cwd = scanCwd(fs);
    const own = installations.find(i => i.installDir.startsWith(join(fs.homedir(), '/')));
    if (cwd && own) {
      const { root, dirs } = await projectDirs(cwd, fs);
      for (const dir of new Set([root, cwd])) {
        const hooks = await loadHooksWithFallback(PROJECT_HOOKS_FILES.map(rel => join(dir, rel)), fs);
        own.configFiles.push(...await withoutLoadedConfigs(hooks, installations, fs));
      }
      for (const dir of dirs) {
        const skills = join(dir, LEGACY_PROJECT_SKILL_DIR);
        if (!(await fs.access(skills)) || own.skillsDirs?.includes(skills)) continue;
        own.skillsDirs = [...(own.skillsDirs ?? []), skills];
        own.skillsDir ??= skills;
      }
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    const home = fs.homedir();
    return [
      join(codeiumAgentDir(home), MCP_CONFIG_FILE),
      join(devinConfigDir(home, fs), MCP_CONFIG_FILE),
      join(codeiumAgentDir(home), USER_SETTINGS_FILE),
      join(codeiumAgentDir(home), HOOKS_FILE),
      join(devinConfigDir(home, fs), DEVIN_CONFIG_FILE),
      ...editorUserDataDirs(home, fs).map(dir => join(dir, 'User', 'settings.json')),
    ];
  },

  getSkillsDir(_installDir: string): string | undefined {
    // Primary Cascade skill root; detect() records the shared and workspace
    // roots in skillsDirs. Workflows (`// turbo` markdown) are WS-006's.
    const fs = new LocalFSProvider();
    return join(codeiumAgentDir(fs.homedir()), 'skills');
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getMemoryFiles(_installDir: string): string[] {
    // Global rules are always injected into Cascade context; per-memory files
    // live alongside in memories/ (enumerating them needs async fs, so only
    // the fixed path is declared here — the probe manifest globs the rest).
    const fs = new LocalFSProvider();
    return [join(codeiumAgentDir(fs.homedir()), 'memories', 'global_rules.md')];
  },

  getCredentialPaths(_installDir: string, scanFs?: FSProvider): string[] {
    const fs = scanFs ?? new LocalFSProvider();
    const home = fs.homedir();
    return [
      // Legacy plaintext Codeium API key.
      join(home, '.codeium', 'config.json'),
      // state.vscdb ItemTable key `windsurfAuthStatus` holds apiKey
      // (`enc:`-prefixed when encrypted).
      ...editorUserDataDirs(home, fs).map(dir =>
        join(dir, 'User', 'globalStorage', 'state.vscdb')),
    ];
  },

  getCLICommand(): string {
    return 'windsurf';
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/.codeium/windsurf/mcp_config.json',
        '~/.codeium/windsurf/hooks.json',
        '~/.codeium/config.json',
        '~/.codeium/windsurf/memories/global_rules.md',
        '~/.config/devin/mcp_config.json',
        '~/.codeium/windsurf/user_settings.pb',
        '~/.config/devin/config.json',
        '~/Library/Application Support/Windsurf/User/settings.json',
        '~/Library/Application Support/Devin/User/settings.json',
        '~/.config/Windsurf/User/settings.json',
        '~/.config/Devin/User/settings.json',
        // Linux per-user install roots (tarball extracts) → product.json version
        ...HOME_ROOT_NAMES.flatMap(n => [
          `~/${n}/resources/app/product.json`,
          `~/.local/share/${n}/resources/app/product.json`,
        ]),
      ],
      globPatterns: [
        '~/.codeium/windsurf/global_workflows/*.md',
        '~/.codeium/windsurf/memories/*.md',
        // Cascade skill roots — SKL/IOC checks read them
        ...[...OWN_USER_SKILL_DIRS, join('.config', 'devin', 'skills'), ...SHARED_USER_SKILL_DIRS].map(d => `~/${d}/**`),
      ],
      // Editor state DBs hold the auth token: WS-008 / POL-003 need their
      // permissions only — never ship the content.
      metadataGlobPatterns: [
        '~/Library/Application Support/{Windsurf,Devin}/User/globalStorage/state.vscdb',
        '~/.config/{Windsurf,Devin}/User/globalStorage/state.vscdb',
      ],
      commands: [
        { id: 'windsurf-which', cmd: 'which', args: ['windsurf'], timeout: 3000 },
        { id: 'devin-desktop-which', cmd: 'which', args: ['devin-desktop'], timeout: 3000 },
        { id: 'windsurf-version', cmd: 'windsurf', args: ['--version'], timeout: 3000 },
      ],
      directoryListings: [
        '~/.codeium/windsurf',
        '~/.codeium/windsurf/global_workflows',
        '~/.codeium/windsurf/memories',
        '~/Library/Application Support/Windsurf/User/globalStorage',
        '~/Library/Application Support/Devin/User/globalStorage',
        '~/.config/Windsurf/User/globalStorage',
        '~/.config/Devin/User/globalStorage',
      ],
      envPrefixes: ['WINDSURF_', 'CODEIUM_', 'DEVIN_', 'XDG_'],
      systemPaths: [
        ...APP_BUNDLES,
        ...APP_BUNDLES.map(b => join(b, 'Contents', 'Resources', 'app', 'product.json')),
        ...LINUX_SYSTEM_ROOTS.map(r => join(r, 'resources', 'app', 'product.json')),
        ...SYSTEM_CLI_PATHS,
        ...SYSTEM_HOOKS_FILES.darwin,
        ...SYSTEM_HOOKS_FILES.linux,
      ],
      systemDirListings: [],
    };
  },

  // Privilege gradient: untrusted content (MCP servers, web) → the MCP layer
  // and workflow files → Cascade's auto-execution gate (autoExecutionPolicy,
  // command allowlist, turbo directives) → host filesystem + credentials.
  // Inversion fires when turbo/auto execution bypasses the approval gate.
  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Network / Untrusted Content', trustLevel: 0 },
        { id: 'ext', label: 'MCP + Workflows', trustLevel: 1 },
        { id: 'exec', label: 'Cascade Execution Gate', trustLevel: 2 },
        { id: 'host', label: 'Host Filesystem + Credentials', trustLevel: 3 },
      ],
      components: [
        { id: 'inbound', label: 'Network / Remote MCP', zone: 'net' },
        {
          id: 'mcp-workflows',
          label: 'MCP Servers + Workflows',
          zone: 'ext',
          guardCheckIds: ['WS-003', 'WS-004', 'WS-005'],
        },
        {
          id: 'exec-gate',
          label: 'Auto-Execution Policy',
          zone: 'exec',
          guardCheckIds: ['WS-001', 'WS-002', 'WS-006', 'DEV-001'],
        },
        {
          id: 'fs',
          label: 'Host Filesystem + Credentials',
          zone: 'host',
          guardCheckIds: ['WS-007', 'WS-008'],
        },
      ],
      edges: [
        { from: 'inbound', to: 'mcp-workflows', kind: 'data' },
        { from: 'mcp-workflows', to: 'exec-gate', kind: 'control' },
        { from: 'exec-gate', to: 'fs', kind: 'data' },
        {
          from: 'inbound',
          to: 'fs',
          label: 'auto-execution bypass',
          triggerCheckIds: ['WS-001', 'WS-006'],
        },
      ],
    };
  },
};
