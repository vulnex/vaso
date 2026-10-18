import { basename, dirname, isAbsolute, join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ParsedConfig } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { getUserHomeDirs } from './openclaw.js';
import { loadConfigIfPresent } from './load-if-present.js';

/**
 * Grok Bot (SpaceXAI / Cursor, internal name "sand") — a desktop app whose
 * agents run on a cloud computer and reach this machine through a local exec
 * daemon (shell commands, file reads/writes, MCP and AI-tool inventory) when
 * "Execution on Local Computer" allows it. Layout taken from the 0.71.2 Linux
 * .deb (app.asar):
 * - data root (`~/.grokbot`, relocatable with SAND_DATA_ROOT or
 *   SAND_USER_DATA_DIR/sand-data; legacy `~/.cursor/sand`): settings.json,
 *   the sealed local-exec credential, approvals, standing grants, the
 *   computer-use gate and the daemon log.
 * - Electron user data (`~/.config/Grok Bot`, `~/Library/Application
 *   Support/Grok Bot`, `%APPDATA%\Grok Bot`): sand-secrets.json and
 *   user-secrets.json (Electron safeStorage), cookies and client state.
 */
export const GROK_BOT_DATA_DIR = '.grokbot';
const LEGACY_DATA_DIR = join('.cursor', 'sand');
const USER_DATA_NAME = 'Grok Bot';

// The .deb/.rpm install to /opt; the macOS .dmg to /Applications. Windows
// installs per user under %LOCALAPPDATA%\Programs (path name not verified).
const APP_LINUX = '/opt/Grok Bot';
const APP_MAC = '/Applications/Grok Bot.app';
const APT_SOURCE = '/etc/apt/sources.list.d/grok-bot.sources';

/** Files in the data root that the checks read or stat. */
export const DATA_FILES = {
  settings: 'settings.json',
  credential: 'local-exec-daemon-credential.json',
  connection: 'local-exec-daemon-connection.json',
  daemonState: 'local-exec-daemon.json',
  daemonLog: 'local-exec-daemon.log',
  standingGrants: 'local-tool-standing-grants.v1.json',
  approvals: 'local-tool-approvals.json',
  computerUseGate: 'local-computer-use-gate.json',
} as const;

/** Files in the Electron user-data dir that the checks read or stat. */
export const USER_DATA_FILES = {
  secrets: 'sand-secrets.json',
  userSecrets: 'user-secrets.json',
  cookies: 'Cookies',
  status: 'desktop-status.json',
  statsig: 'sand-statsig-bootstrap.json',
  clientPersistence: 'sand-client-persistence',
  reliability: 'dune-reliability',
} as const;

/** Environment variables the adapter and checks read (none holds a secret). */
export const GROK_BOT_ENV = [
  'SAND_DATA_ROOT', 'SAND_USER_DATA_DIR', 'SAND_LOCAL_EXEC_ROOT',
  'SAND_DISABLE_UPDATES', 'SAND_EGRESS_TUNNEL_ALLOW_PRIVATE',
];

function envDir(fs: FSProvider, name: string): string | undefined {
  const v = fs.getEnv(name)?.trim();
  return v && isAbsolute(v) ? v : undefined;
}

/** Environment overrides describe the scanning user's session only. */
function ownSession(home: string, fs: FSProvider): boolean {
  return home === fs.homedir();
}

/** Electron user-data dir (`app.getPath('userData')`). */
export function grokBotUserDataDir(home: string, fs: FSProvider): string {
  const override = ownSession(home, fs) ? envDir(fs, 'SAND_USER_DATA_DIR') : undefined;
  if (override) return override;
  if (fs.platform === 'darwin') return join(home, 'Library', 'Application Support', USER_DATA_NAME);
  if (fs.platform === 'win32') {
    const appData = fs.getEnv('APPDATA')?.trim();
    return join(appData || join(home, 'AppData', 'Roaming'), USER_DATA_NAME);
  }
  const xdg = ownSession(home, fs) ? envDir(fs, 'XDG_CONFIG_HOME') : undefined;
  return join(xdg || join(home, '.config'), USER_DATA_NAME);
}

/**
 * The data root as the app resolves it: SAND_DATA_ROOT (absolute), then
 * <SAND_USER_DATA_DIR>/sand-data, then ~/.grokbot — or the pre-rename
 * ~/.cursor/sand when only that exists.
 */
export async function grokBotDataRoot(home: string, fs: FSProvider): Promise<string> {
  if (ownSession(home, fs)) {
    const root = envDir(fs, 'SAND_DATA_ROOT');
    if (root) return root;
    const userData = envDir(fs, 'SAND_USER_DATA_DIR');
    if (userData) return join(userData, 'sand-data');
  }
  const current = join(home, GROK_BOT_DATA_DIR);
  if (await fs.access(current)) return current;
  const legacy = join(home, LEGACY_DATA_DIR);
  if (await fs.access(join(legacy, DATA_FILES.settings))) return legacy;
  return current;
}

/** Home directory an installation belongs to, from its data root. */
export function grokBotHome(installDir: string, fs: FSProvider): string {
  if (basename(installDir) === GROK_BOT_DATA_DIR) return dirname(installDir);
  if (installDir.endsWith(`${'/'}${LEGACY_DATA_DIR.replace(/\\/g, '/')}`)) return dirname(dirname(installDir));
  return fs.homedir();
}

function appPath(fs: FSProvider): string | undefined {
  if (fs.platform === 'darwin') return APP_MAC;
  if (fs.platform === 'linux') return APP_LINUX;
  const local = fs.getEnv('LOCALAPPDATA')?.trim();
  return local ? join(local, 'Programs', USER_DATA_NAME) : undefined;
}

/**
 * Version: desktop-status.json (`appVersion`, written by the running app) or,
 * on macOS, the bundle's Info.plist. The .deb keeps it only inside app.asar.
 */
async function readVersion(userData: string, app: string | undefined, fs: FSProvider): Promise<string | undefined> {
  try {
    const status = JSON.parse(await fs.readFile(join(userData, USER_DATA_FILES.status))) as { appVersion?: unknown };
    if (typeof status.appVersion === 'string' && /^\d+\.\d+/.test(status.appVersion)) return status.appVersion;
  } catch {}
  if (fs.platform === 'darwin' && app) {
    try {
      const r = await fs.exec('defaults', ['read', `${app}/Contents/Info.plist`, 'CFBundleShortVersionString'], { timeout: 3000 });
      const v = r.stdout.trim();
      if (r.exitCode === 0 && v) return v;
    } catch {}
  }
  return undefined;
}

export const grokBotAdapter: AgentAdapter = {
  agent: 'grok-bot',
  displayName: 'Grok Bot',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];
    const app = appPath(fs);
    const appInstalled = app ? await fs.access(app) : false;

    for (const { home, user } of userDirs) {
      const dataRoot = await grokBotDataRoot(home, fs);
      const userData = grokBotUserDataDir(home, fs);
      const hasDataRoot = await fs.access(dataRoot);
      const hasUserData = await fs.access(userData);
      // The app alone counts only for the scanning user: a system install
      // says nothing about other accounts that never launched it
      if (!hasDataRoot && !hasUserData && !(appInstalled && ownSession(home, fs))) continue;

      const configFiles: ParsedConfig[] = [];
      const settings = await loadConfigIfPresent(join(dataRoot, DATA_FILES.settings), fs);
      if (settings && settings.data && typeof settings.data === 'object' && !Array.isArray(settings.data)) {
        configFiles.push(settings);
      }

      installations.push({
        agent: 'grok-bot',
        version: await readVersion(userData, appInstalled ? app : undefined, fs),
        installDir: dataRoot,
        configFiles,
        user: options?.allUsers ? user : undefined,
        appBundle: appInstalled ? app : undefined,
      });
    }
    return installations;
  },

  getConfigPaths(): string[] {
    return [join(new LocalFSProvider().homedir(), GROK_BOT_DATA_DIR, DATA_FILES.settings)];
  },

  getSkillsDir(_installDir: string): string | undefined {
    // Skills, plugins and memories live on the cloud computer, per Bot
    return undefined;
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    // No local listener: the exec daemon dials out to the Cursor backend
    return undefined;
  },

  getMemoryFiles(): string[] {
    return [];
  },

  getCredentialPaths(installDir: string, fs?: FSProvider): string[] {
    const provider = fs ?? new LocalFSProvider();
    const userData = grokBotUserDataDir(grokBotHome(installDir, provider), provider);
    return [
      join(installDir, DATA_FILES.credential),
      join(installDir, DATA_FILES.connection),
      join(userData, USER_DATA_FILES.secrets),
      join(userData, USER_DATA_FILES.userSecrets),
      join(userData, USER_DATA_FILES.cookies),
    ];
  },

  getProbeManifest(): ProbeManifest {
    const root = `~/${GROK_BOT_DATA_DIR}`;
    const legacy = `~/${LEGACY_DATA_DIR.replace(/\\/g, '/')}`;
    const userDataDirs = [`~/.config/${USER_DATA_NAME}`, `~/Library/Application Support/${USER_DATA_NAME}`];
    const settingsFiles = [DATA_FILES.settings, DATA_FILES.computerUseGate];
    return {
      filePaths: [
        ...[root, legacy].flatMap(d => settingsFiles.map(f => `${d}/${f}`)),
        ...userDataDirs.map(d => `${d}/${USER_DATA_FILES.status}`),
      ],
      globPatterns: [],
      // Credentials, approvals, logs and client state: existence and
      // permissions only, never content (GB-006 reads content only locally)
      metadataGlobPatterns: [
        ...[root, legacy].flatMap(d => [
          DATA_FILES.credential, DATA_FILES.connection, DATA_FILES.daemonState,
          DATA_FILES.daemonLog, DATA_FILES.approvals,
          // Recipients are contacts — GB-004 reads it only locally
          DATA_FILES.standingGrants,
        ].map(f => `${d}/${f}`)),
        ...userDataDirs.flatMap(d => [
          USER_DATA_FILES.secrets, USER_DATA_FILES.userSecrets, USER_DATA_FILES.cookies,
          USER_DATA_FILES.statsig, `${USER_DATA_FILES.reliability}/*`,
          // The directories themselves (mode only, never listed): the
          // sand-client-persistence blob names encode the account id
          USER_DATA_FILES.clientPersistence, USER_DATA_FILES.reliability,
        ].map(f => `${d}/${f}`)),
      ],
      commands: [
        { id: 'grok-bot-version', cmd: 'defaults', args: ['read', `${APP_MAC}/Contents/Info.plist`, 'CFBundleShortVersionString'], timeout: 3000 },
      ],
      directoryListings: [root, legacy, ...userDataDirs],
      // Named variables only: a bare SAND_ prefix would ship values such as
      // SAND_EGRESS_TUNNEL_BEARER, which the probe's name-based redaction misses
      envPrefixes: GROK_BOT_ENV,
      systemPaths: [APP_LINUX, APP_MAC, APT_SOURCE],
      systemDirListings: [],
    };
  },
};

export { APT_SOURCE as GROK_BOT_APT_SOURCE };
