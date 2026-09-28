import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ParsedConfig } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { getUserHomeDirs } from './openclaw.js';
import { loadPlistAsConfig } from './plist-config.js';

// Meta Muse desktop agent (macOS). Bundle ID / internal codename: "endo".
// Initial coverage: the agent is US-region-gated, so only the pre-configuration
// surface (app bundle, Sparkle updater, analytics, preferences plist) is
// mapped. Expand once a configured install is available for survey.
const APP_BUNDLE_PATH = '/Applications/Muse.app';
const BUNDLE_ID = 'com.meta.endo';
const PREFS_PLIST = `${BUNDLE_ID}.plist`;

async function readAppVersion(fs: FSProvider): Promise<string | undefined> {
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

export const metaMuseAdapter: AgentAdapter = {
  agent: 'meta-muse',
  displayName: 'Meta Muse',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    if (fs.platform !== 'darwin') return [];

    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    const appExists = await fs.access(APP_BUNDLE_PATH);
    const version = appExists ? await readAppVersion(fs) : undefined;

    for (const { home, user } of userDirs) {
      const supportDir = join(home, 'Library', 'Application Support', BUNDLE_ID);
      const hasSupportDir = await fs.access(supportDir);
      if (!appExists && !hasSupportDir) continue;

      const configFiles: ParsedConfig[] = [];
      const prefsPath = join(home, 'Library', 'Preferences', PREFS_PLIST);
      const prefs = await loadPlistAsConfig(prefsPath, fs);
      if (prefs) configFiles.push(prefs);

      installations.push({
        agent: 'meta-muse',
        version,
        installDir: supportDir,
        configFiles,
        user: options?.allUsers ? user : undefined,
        appBundle: appExists ? APP_BUNDLE_PATH : undefined,
      });
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    if (fs.platform !== 'darwin') return [];
    return [join(fs.homedir(), 'Library', 'Preferences', PREFS_PLIST)];
  },

  getSkillsDir(_installDir: string): string | undefined {
    return undefined;
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getMemoryFiles(): string[] {
    return [];
  },

  getCredentialPaths(installDir: string): string[] {
    // Auth is expected in the keychain; the on-disk identity material observed
    // so far is the analytics store under Application Support.
    return [installDir];
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [`~/Library/Preferences/${PREFS_PLIST}`],
      globPatterns: [],
      // App data (analytics store, caches) is private — MM-003 checks
      // permissions only, so collect existence + mode, never content.
      metadataGlobPatterns: [`~/Library/Application Support/${BUNDLE_ID}/**`],
      commands: [
        { id: 'muse-version', cmd: 'defaults', args: ['read', `${APP_BUNDLE_PATH}/Contents/Info.plist`, 'CFBundleShortVersionString'], timeout: 3000 },
        { id: 'muse-codesign', cmd: 'codesign', args: ['-dv', APP_BUNDLE_PATH], timeout: 5000 },
        { id: 'muse-plist-main', cmd: 'plutil', args: ['-convert', 'xml1', '-o', '-', `~/Library/Preferences/${PREFS_PLIST}`], timeout: 3000 },
      ],
      directoryListings: [`~/Library/Application Support/${BUNDLE_ID}`],
      envPrefixes: [],
      systemPaths: [APP_BUNDLE_PATH],
      systemDirListings: [],
    };
  },
};
