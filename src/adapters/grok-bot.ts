import { basename, dirname, isAbsolute, join } from 'node:path';
import { gunzipSync } from 'node:zlib';
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
 * .deb and the 0.78.4 macOS .app (app.asar):
 * - data root (`~/.grokbot`, relocatable with SAND_DATA_ROOT or
 *   SAND_USER_DATA_DIR/sand-data; legacy `~/.cursor/sand`): settings.json,
 *   the sealed local-exec credential, approvals, standing grants, the
 *   computer-use gate and the daemon log.
 * - Electron user data (`~/.config/Grok Bot`, `~/Library/Application
 *   Support/Grok Bot`, `%APPDATA%\Grok Bot` — or the pre-rename
 *   `%APPDATA%\Sand` until an update migrates it): sand-secrets.json and
 *   user-secrets.json (Electron safeStorage), cookies and client state.
 */
export const GROK_BOT_DATA_DIR = '.grokbot';
const LEGACY_DATA_DIR = join('.cursor', 'sand');
const USER_DATA_NAME = 'Grok Bot';
// Windows only: the pre-rename user-data dir and the marker the app writes
// into %APPDATA%\Grok Bot once it owns it
const LEGACY_USER_DATA_NAME = 'Sand';
const USER_DATA_MARKER = '.grokbot-user-data-v1';

// The .deb/.rpm install to /opt; the macOS .dmg to /Applications. Windows
// installs per user under %LOCALAPPDATA%\Programs (path name not verified).
const APP_LINUX = '/opt/Grok Bot';
const APP_MAC = '/Applications/Grok Bot.app';
const APT_SOURCE = '/etc/apt/sources.list.d/grok-bot.sources';
// Package metadata of a .deb install: FPM's changelog (first line
// "grok-bot (<version>) ; …", replaced on every upgrade) and dpkg's database
const DEB_CHANGELOG = '/usr/share/doc/grok-bot/changelog.gz';
const DPKG_STATUS = '/var/lib/dpkg/status';

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
  // macOS (0.78+): mirrors the server flag that offers Reminders, Calendar,
  // Contacts, Notes and Mail to the cloud agent
  macDeviceToolsGate: 'mac-device-tools-gate.json',
  // Single-use send approvals already spent, and approvals withdrawn: the
  // daemon consults both before honouring an approval (0.78)
  spentSends: 'local-tool-spent-sends.json',
  retirements: 'local-tool-retirements.json',
  // A plaintext Cursor access token that only unpackaged (development) builds
  // write, refreshed every minute while signed in (0.78)
  hostToken: 'host-token.json',
  // macOS: the daemon copies the signed Computer Use helper out of the app
  // bundle into this dir and launches the copy
  computerUseDir: 'computer-use',
} as const;

/** macOS Computer Use helper (0.78.4 "prod" sidecar profile). */
export const GROK_BOT_HELPER = {
  app: 'Grok Bot Computer Use.app',
  bundleId: 'co.anysphere.grok-bot-computer-use',
  executable: 'CUGrokBotService',
  // ~/Library/Application Support/<dir>/service.json names the helper's RPC socket
  supportDir: 'grok-bot-computer-use',
  serviceFile: 'service.json',
} as const;

/** Signing identity of the macOS app and its helper (verified on 0.78.4). */
export const GROK_BOT_TEAM_ID = 'DCNK4UB866';
export const GROK_BOT_BUNDLE_ID = 'com.anysphere.sand';

/** Files in the Electron user-data dir that the checks read or stat. */
export const USER_DATA_FILES = {
  secrets: 'sand-secrets.json',
  userSecrets: 'user-secrets.json',
  cookies: 'Cookies',
  status: 'desktop-status.json',
  statsig: 'sand-statsig-bootstrap.json',
  clientPersistence: 'sand-client-persistence',
  reliability: 'dune-reliability',
  // Written the first time the app connects through SAND_HOST_GATEWAY_URL
  gatewayBindings: '.env-descriptor-account-bindings.json',
} as const;

/** Endpoint overrides GB-012 judges by origin only: the probe keeps scheme,
 *  host and port, never the path or query (account ids, tokens). */
const GROK_BOT_URL_ENV = [
  'SAND_EGRESS_TUNNEL_URL', 'SAND_BACKEND_URL', 'CURSOR_API_BASE_URL', 'SAND_HOST_GATEWAY_URL',
  'SAND_CURSOR_WEBSITE_URL', 'CURSOR_WEBSITE_URL', 'SAND_HTTPS_PROXY',
];

/** Environment variables the adapter and checks read (none holds a secret). */
export const GROK_BOT_ENV = [
  'SAND_DATA_ROOT', 'SAND_USER_DATA_DIR', 'SAND_LOCAL_EXEC_ROOT',
  'SAND_DISABLE_UPDATES', 'SAND_EGRESS_TUNNEL_ALLOW_PRIVATE',
  // Locations only — gateway tokens are never collected (the probe also strips
  // user:password@ from URLs). The tunnel bearer is collected for presence
  // only: the probe redacts every *_BEARER value (probe ≥ 1.4.0)
  'SAND_EGRESS_TUNNEL_URL', 'SAND_EGRESS_TUNNEL_BEARER',
  // Endpoint overrides honoured by packaged builds (GB-012)
  'SAND_BACKEND_URL', 'CURSOR_API_BASE_URL', 'SAND_HOST_GATEWAY_URL',
  'SAND_CURSOR_WEBSITE_URL', 'CURSOR_WEBSITE_URL',
  'SAND_HTTPS_PROXY', 'SAND_SYSTEM_PROXY', 'NODE_USE_ENV_PROXY',
  // macOS: replaces the Computer Use helper app (a path, GB-016)
  'GROK_BOT_SIDECAR_APP',
];

function envDir(fs: FSProvider, name: string): string | undefined {
  const v = fs.getEnv(name)?.trim();
  return v && isAbsolute(v) ? v : undefined;
}

/** Environment overrides describe the scanning user's session only. */
function ownSession(home: string, fs: FSProvider): boolean {
  return home === fs.homedir();
}

function userDataOverride(home: string, fs: FSProvider): string | undefined {
  return ownSession(home, fs) ? envDir(fs, 'SAND_USER_DATA_DIR') : undefined;
}

function windowsAppData(home: string, fs: FSProvider): string {
  const appData = ownSession(home, fs) ? fs.getEnv('APPDATA')?.trim() : undefined;
  return appData || join(home, 'AppData', 'Roaming');
}

/**
 * Electron user-data dir (`app.getPath('userData')`) under its current name.
 * On Windows the app may still run from the pre-rename %APPDATA%\Sand —
 * `resolveGrokBotUserDataDir` decides that; this is the canonical path.
 */
export function grokBotUserDataDir(home: string, fs: FSProvider): string {
  const override = userDataOverride(home, fs);
  if (override) return override;
  if (fs.platform === 'darwin') return join(home, 'Library', 'Application Support', USER_DATA_NAME);
  if (fs.platform === 'win32') return join(windowsAppData(home, fs), USER_DATA_NAME);
  const xdg = ownSession(home, fs) ? envDir(fs, 'XDG_CONFIG_HOME') : undefined;
  return join(xdg || join(home, '.config'), USER_DATA_NAME);
}

/** Every user-data dir the app may be using (both names on Windows). */
export function grokBotUserDataDirs(home: string, fs: FSProvider): string[] {
  const canonical = grokBotUserDataDir(home, fs);
  if (fs.platform !== 'win32' || userDataOverride(home, fs)) return [canonical];
  return [canonical, join(windowsAppData(home, fs), LEGACY_USER_DATA_NAME)];
}

type DirState = 'absent' | 'directory' | 'unsafe';

/** lstat-style state of `<parent>\<name>` (a link or a file is "unsafe"). */
async function dirState(parent: string, name: string, fs: FSProvider): Promise<DirState> {
  try {
    const entry = (await fs.readdirEntries(parent))
      .find(e => e.name.toLowerCase() === name.toLowerCase());
    if (!entry) return 'absent';
    return entry.isDirectory && !entry.isSymbolicLink ? 'directory' : 'unsafe';
  } catch {
    return (await fs.access(join(parent, name))) ? 'unsafe' : 'absent';
  }
}

/**
 * The user-data dir the app runs from. On Windows, packaged builds keep the
 * pre-rename %APPDATA%\Sand until an update relaunch moves it to
 * %APPDATA%\Grok Bot: Sand stays in use while it exists, unless Grok Bot
 * carries the app's marker or already holds data — and when Sand is a link or
 * a file, or Grok Bot is (the app won't migrate through one), as the 0.71.2
 * settlement does.
 */
export async function resolveGrokBotUserDataDir(home: string, fs: FSProvider): Promise<string> {
  const canonical = grokBotUserDataDir(home, fs);
  if (fs.platform !== 'win32' || userDataOverride(home, fs)) return canonical;
  const appData = windowsAppData(home, fs);
  const legacy = join(appData, LEGACY_USER_DATA_NAME);
  const legacyState = await dirState(appData, LEGACY_USER_DATA_NAME, fs);
  if (legacyState === 'absent') return canonical;
  if (legacyState === 'unsafe') return legacy;
  const canonicalState = await dirState(appData, USER_DATA_NAME, fs);
  if (canonicalState !== 'directory') return legacy;
  if (await fs.access(join(canonical, USER_DATA_MARKER))) return canonical;
  try {
    // An empty Grok Bot dir waits for the migration; one with data is kept
    return (await fs.readdir(canonical)).length > 0 ? canonical : legacy;
  } catch {
    return legacy;
  }
}

/** The scanning user's env-relocated data root, if any. */
function relocatedDataRoot(fs: FSProvider): string | undefined {
  const root = envDir(fs, 'SAND_DATA_ROOT');
  if (root) return root;
  const userData = envDir(fs, 'SAND_USER_DATA_DIR');
  return userData ? join(userData, 'sand-data') : undefined;
}

// Written once the app has settled on ~/.grokbot (after migrating ~/.cursor/sand)
const DATA_ROOT_MARKER = '.grokbot-data-root-v1';

/**
 * The data root as the app resolves it: SAND_DATA_ROOT (absolute), then
 * <SAND_USER_DATA_DIR>/sand-data, then ~/.grokbot — or the pre-rename
 * ~/.cursor/sand while that holds settings and ~/.grokbot carries no
 * migration marker (a stray ~/.grokbot doesn't move the app).
 */
export async function grokBotDataRoot(home: string, fs: FSProvider): Promise<string> {
  const relocated = ownSession(home, fs) ? relocatedDataRoot(fs) : undefined;
  if (relocated) return relocated;
  const current = join(home, GROK_BOT_DATA_DIR);
  if (await fs.access(join(current, DATA_ROOT_MARKER))) return current;
  const legacy = join(home, LEGACY_DATA_DIR);
  if (await fs.access(join(legacy, DATA_FILES.settings))) return legacy;
  return current;
}

/** Home directory an installation belongs to, from its data root. */
export function grokBotHome(installDir: string, fs: FSProvider): string {
  // A relocated root may itself be named .grokbot (/data/.grokbot) — it is
  // still the scanning user's
  if (relocatedDataRoot(fs) === installDir) return fs.homedir();
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

const VERSION = /^\d+\.\d+(?:\.\d+)?(?:[-+~][0-9A-Za-z.+~-]*)?$/;

/** `Version:` of the installed grok-bot stanza in dpkg's status file. */
export function dpkgVersion(status: string): string | undefined {
  for (const stanza of status.split(/\n[ \t]*\n/)) {
    if (!/^Package: grok-bot[ \t]*$/m.test(stanza)) continue;
    // A removed package keeps its stanza ("deinstall ok config-files")
    if (!/^Status: [a-z]+ ok installed[ \t]*$/m.test(stanza)) return undefined;
    const v = /^Version: (\S+)[ \t]*$/m.exec(stanza)?.[1];
    return v && VERSION.test(v) ? v : undefined;
  }
  return undefined;
}

/**
 * A .deb install's version, for an app that has never run (no
 * desktop-status.json yet): FPM's changelog.gz, else dpkg's status file
 * (images that drop /usr/share/doc). Remote scans get neither — the probe
 * ships no .gz content, and the status file is the host's whole package
 * inventory — so a never-launched .deb has no version there.
 */
async function debVersion(fs: FSProvider): Promise<string | undefined> {
  try {
    const head = gunzipSync(await fs.readBytes(DEB_CHANGELOG), { maxOutputLength: 1 << 20 }).toString('utf8');
    const v = /^grok-bot \(([^)\s]+)\)/.exec(head)?.[1];
    if (v && VERSION.test(v)) return v;
  } catch {}
  try {
    return dpkgVersion(await fs.readFile(DPKG_STATUS));
  } catch {}
  return undefined;
}

/**
 * Version: desktop-status.json (`appVersion`, written by the running app) or,
 * on macOS, the bundle's Info.plist; a .deb that never ran, from its package
 * metadata (local scans only).
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
  if (fs.platform === 'linux' && app === APP_LINUX) return debVersion(fs);
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
      const userData = await resolveGrokBotUserDataDir(home, fs);
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
    // Both user-data names on Windows: which one is live needs I/O
    const userDataDirs = grokBotUserDataDirs(grokBotHome(installDir, provider), provider);
    return [
      join(installDir, DATA_FILES.credential),
      join(installDir, DATA_FILES.connection),
      ...userDataDirs.flatMap(d => [
        join(d, USER_DATA_FILES.secrets),
        join(d, USER_DATA_FILES.userSecrets),
        join(d, USER_DATA_FILES.cookies),
      ]),
    ];
  },

  getProbeManifest(): ProbeManifest {
    const root = `~/${GROK_BOT_DATA_DIR}`;
    const legacy = `~/${LEGACY_DATA_DIR.replace(/\\/g, '/')}`;
    const userDataDirs = [`~/.config/${USER_DATA_NAME}`, `~/Library/Application Support/${USER_DATA_NAME}`];
    const settingsFiles = [DATA_FILES.settings, DATA_FILES.computerUseGate, DATA_FILES.macDeviceToolsGate];
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
          DATA_FILES.spentSends, DATA_FILES.retirements,
          // A plaintext access token (development builds): never content
          DATA_FILES.hostToken,
          // The helper copy: modes only (GB-016)
          DATA_FILES.computerUseDir,
          `${DATA_FILES.computerUseDir}/${GROK_BOT_HELPER.app}`,
          `${DATA_FILES.computerUseDir}/${GROK_BOT_HELPER.app}/Contents/MacOS/${GROK_BOT_HELPER.executable}`,
        ].map(f => `${d}/${f}`)),
        `~/Library/Application Support/${GROK_BOT_HELPER.supportDir}`,
        `~/Library/Application Support/${GROK_BOT_HELPER.supportDir}/${GROK_BOT_HELPER.serviceFile}`,
        // The app GROK_BOT_SIDECAR_APP names in place of the helper: whether
        // it exists decides GB-016's severity — existence and mode only
        '${GROK_BOT_SIDECAR_APP}',
        ...userDataDirs.flatMap(d => [
          USER_DATA_FILES.secrets, USER_DATA_FILES.userSecrets, USER_DATA_FILES.cookies,
          USER_DATA_FILES.statsig, `${USER_DATA_FILES.reliability}/*`,
          USER_DATA_FILES.gatewayBindings,
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
      envOriginOnly: GROK_BOT_URL_ENV,
      systemPaths: [APP_LINUX, APP_MAC, APT_SOURCE],
      systemDirListings: [],
    };
  },
};

export { APT_SOURCE as GROK_BOT_APT_SOURCE, APP_LINUX as GROK_BOT_APP_LINUX };
