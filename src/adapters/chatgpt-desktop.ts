import { join } from 'node:path';
import { readFile } from 'node:fs/promises';
import * as plist from 'plist';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { getUserHomeDirs } from './openclaw.js';

const APP_BUNDLE_PATH = '/Applications/ChatGPT.app';
const BUNDLE_ID = 'com.openai.chat';
const APP_SUPPORT_REL = ['Library', 'Application Support', BUNDLE_ID];
const PREFS_REL = ['Library', 'Preferences'];

const PLISTS = {
  main: 'com.openai.chat.plist',
  helper: 'ChatGPTHelper.plist',
  statsig: 'com.openai.chat.StatsigService.plist',
  // Workspace-namespaced; real filename is com.openai.chat.RemoteFeatureFlags.<workspace>.plist.
  // Resolved at runtime by listing the Preferences dir.
  remoteFlagsPrefix: 'com.openai.chat.RemoteFeatureFlags.',
};

const PAIRING_DIR = 'app_pairing_extensions';

/**
 * Parse a macOS plist (XML or binary) into a plain object. Uses the `plist`
 * npm package because plutil refuses to convert NSDate/NSData-bearing plists
 * to JSON, and ChatGPT's preferences include both. Date values surface as
 * Date instances and are serialized as ISO strings before reaching checks.
 */
async function loadPlistAsObject(filePath: string, fs: FSProvider): Promise<Record<string, unknown> | undefined> {
  if (!(await fs.access(filePath))) return undefined;
  try {
    // The plist package only accepts string/Buffer of file contents, not paths.
    // Use the underlying fs/promises directly — testable plist content arrives
    // through fs.readFile in the LocalFSProvider; SnapshotFSProvider returns
    // text for XML plists. Binary plists in snapshots aren't supported here
    // and will fall back to undefined.
    const isLocal = fs.platform === 'darwin' && fs instanceof LocalFSProvider;
    const buf = isLocal
      ? await readFile(filePath)
      : Buffer.from(await fs.readFile(filePath));
    const parsed = plist.parse(buf as unknown as string) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
    return normalizeForJson(parsed as Record<string, unknown>);
  } catch {
    return undefined;
  }
}

/**
 * Recursively replace `Date` and `Buffer` values with serializable forms so
 * the resulting object is safe to embed in `ParsedConfig.raw` (a JSON string)
 * and consumed by checks that don't expect non-JSON types.
 */
function normalizeForJson(value: unknown): Record<string, unknown> {
  if (value instanceof Date) return { __date: value.toISOString() } as unknown as Record<string, unknown>;
  if (Buffer.isBuffer(value)) return { __data: value.toString('base64') } as unknown as Record<string, unknown>;
  if (Array.isArray(value)) {
    return (value.map(v => normalizeValue(v)) as unknown) as Record<string, unknown>;
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = normalizeValue(v);
    }
    return out;
  }
  return value as Record<string, unknown>;
}

function normalizeValue(value: unknown): unknown {
  if (value instanceof Date) return value.toISOString();
  if (Buffer.isBuffer(value)) return value.toString('base64');
  if (Array.isArray(value)) return value.map(normalizeValue);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = normalizeValue(v);
    }
    return out;
  }
  return value;
}

/**
 * Wrap a plist's parsed contents as a ParsedConfig so the existing scanning
 * pipeline (which iterates `ctx.configs`) can consume them. We label the
 * format as 'json' since plutil emits JSON; the original file is a plist.
 */
function asConfig(filePath: string, data: Record<string, unknown>): ParsedConfig {
  return {
    raw: JSON.stringify(data),
    format: 'json',
    filePath,
    data,
  };
}

async function findRemoteFlagsPlist(prefsDir: string, fs: FSProvider): Promise<string | undefined> {
  try {
    const entries = await fs.readdirEntries(prefsDir);
    for (const e of entries) {
      if (!e.isFile) continue;
      if (e.name.startsWith(PLISTS.remoteFlagsPrefix) && e.name.endsWith('.plist')) {
        return join(prefsDir, e.name);
      }
    }
  } catch {}
  return undefined;
}

async function readAppVersion(fs: FSProvider): Promise<string | undefined> {
  if (!(await fs.access(APP_BUNDLE_PATH))) return undefined;
  try {
    const result = await fs.exec(
      'defaults',
      ['read', `${APP_BUNDLE_PATH}/Contents/Info.plist`, 'CFBundleShortVersionString'],
      { timeout: 3000 },
    );
    if (result.exitCode === 0) {
      const v = result.stdout.trim();
      if (v.length > 0) return v;
    }
  } catch {}
  return undefined;
}

export const chatgptDesktopAdapter: AgentAdapter = {
  agent: 'chatgpt-desktop',
  displayName: 'ChatGPT Desktop',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    if (fs.platform !== 'darwin') return [];

    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    const appExists = await fs.access(APP_BUNDLE_PATH);
    const version = appExists ? await readAppVersion(fs) : undefined;

    for (const { home, user } of userDirs) {
      const supportDir = join(home, ...APP_SUPPORT_REL);
      const prefsDir = join(home, ...PREFS_REL);

      const hasSupportDir = await fs.access(supportDir);
      if (!hasSupportDir && !appExists) continue;

      const configFiles: ParsedConfig[] = [];

      const mainPath = join(prefsDir, PLISTS.main);
      const mainData = await loadPlistAsObject(mainPath, fs);
      if (mainData) configFiles.push(asConfig(mainPath, mainData));

      const statsigPath = join(prefsDir, PLISTS.statsig);
      const statsigData = await loadPlistAsObject(statsigPath, fs);
      if (statsigData) configFiles.push(asConfig(statsigPath, statsigData));

      const remoteFlagsPath = await findRemoteFlagsPlist(prefsDir, fs);
      if (remoteFlagsPath) {
        const flags = await loadPlistAsObject(remoteFlagsPath, fs);
        if (flags) configFiles.push(asConfig(remoteFlagsPath, flags));
      }

      const helperPath = join(prefsDir, PLISTS.helper);
      const helperData = await loadPlistAsObject(helperPath, fs);
      if (helperData) configFiles.push(asConfig(helperPath, helperData));

      installations.push({
        agent: 'chatgpt-desktop',
        version,
        installDir: supportDir,
        configFiles,
        models: this.getModels?.(configFiles) as ModelRef[] | undefined,
        user: options?.allUsers ? user : undefined,
        appBundle: appExists ? APP_BUNDLE_PATH : undefined,
      });
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    if (fs.platform !== 'darwin') return [];
    const home = fs.homedir();
    const prefsDir = join(home, ...PREFS_REL);
    return [
      join(prefsDir, PLISTS.main),
      join(prefsDir, PLISTS.statsig),
      join(prefsDir, PLISTS.helper),
    ];
  },

  getSkillsDir(installDir: string): string | undefined {
    // ChatGPT's nearest "skills"-equivalent is paired connectors / Apps. The
    // dir exists but contents are JSON state crumbs, not executable code, so
    // skill code analysis doesn't apply.
    return join(installDir, PAIRING_DIR);
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    // ChatGPT persists the active model inside a JSON blob string in the main
    // plist: `lastAccountSettingsResponse_<workspace>` →
    // settings.lastUsedModelConfig.slugs.{default|web|iosApp}.
    for (const file of configs) {
      if (!file.filePath.endsWith(PLISTS.main)) continue;
      for (const [k, v] of Object.entries(file.data)) {
        if (!k.startsWith('lastAccountSettingsResponse_')) continue;
        if (typeof v !== 'string') continue;
        try {
          const parsed = JSON.parse(v) as Record<string, unknown>;
          const settings = parsed.settings as Record<string, unknown> | undefined;
          const cfg = settings?.lastUsedModelConfig as Record<string, unknown> | undefined;
          const slugs = cfg?.slugs as Record<string, unknown> | undefined;
          const def = slugs?.default;
          if (typeof def === 'string' && def.length > 0) {
            return [{ id: def, provider: 'openai' }];
          }
        } catch {}
      }
    }
    return [];
  },

  getMemoryFiles(): string[] {
    return [];
  },

  getCredentialPaths(installDir: string): string[] {
    // ChatGPT stores session/auth in the keychain, not on disk. The closest
    // disk-resident identity material is StatsigService.plist (account email)
    // and the workspace-keyed conversation store.
    return [installDir];
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/Library/Preferences/com.openai.chat.plist',
        '~/Library/Preferences/com.openai.chat.StatsigService.plist',
        '~/Library/Preferences/ChatGPTHelper.plist',
      ],
      globPatterns: [
        '~/Library/Preferences/com.openai.chat.RemoteFeatureFlags.*.plist',
        '~/Library/Application Support/com.openai.chat/app_pairing_extensions/**',
        '~/Library/Application Support/com.openai.chat/conversations-v3-*/**',
      ],
      commands: [
        { id: 'chatgpt-version', cmd: 'defaults', args: ['read', `${APP_BUNDLE_PATH}/Contents/Info.plist`, 'CFBundleShortVersionString'], timeout: 3000 },
        { id: 'chatgpt-codesign', cmd: 'codesign', args: ['-dv', APP_BUNDLE_PATH], timeout: 5000 },
      ],
      directoryListings: [
        '~/Library/Application Support/com.openai.chat',
        '~/Library/Application Support/com.openai.chat/app_pairing_extensions',
        '~/Library/Preferences',
      ],
      envPrefixes: ['OPENAI_'],
      systemPaths: [APP_BUNDLE_PATH],
      systemDirListings: [],
    };
  },

  // Privilege gradient: untrusted network → on-disk artifacts (encrypted but
  // mode-permissive) → app capability surface (Apple Events, paired connectors)
  // → host filesystem reach. Inversion fires when the .app bundle codesign
  // doesn't match the expected Team ID — that's a swapped/impersonated app
  // running under the user's existing TCC grants.
  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Network / Cloud', trustLevel: 0 },
        { id: 'disk', label: 'On-disk Artifacts', trustLevel: 1 },
        { id: 'cap', label: 'App Capabilities', trustLevel: 2 },
        { id: 'host', label: 'Host Reach', trustLevel: 3 },
      ],
      components: [
        { id: 'inbound', label: 'Network / Sentry', zone: 'net' },
        {
          id: 'artifacts',
          label: 'Conversations + Drafts',
          zone: 'disk',
          guardCheckIds: ['CG-001', 'CG-002'],
        },
        {
          id: 'capabilities',
          label: 'Privacy + Connector Caps',
          zone: 'cap',
          guardCheckIds: ['CG-003', 'CG-004', 'CG-006'],
        },
        {
          id: 'host',
          label: 'Apple Events / Apps',
          zone: 'host',
          guardCheckIds: ['CG-005'],
        },
      ],
      edges: [
        { from: 'inbound', to: 'artifacts', kind: 'data' },
        { from: 'artifacts', to: 'capabilities', kind: 'control' },
        { from: 'capabilities', to: 'host', kind: 'data' },
        {
          from: 'inbound',
          to: 'host',
          label: 'app impersonation',
          triggerCheckIds: ['CG-005'],
        },
      ],
    };
  },
};
