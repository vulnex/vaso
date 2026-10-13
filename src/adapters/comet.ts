import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ParsedConfig } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { getUserHomeDirs } from './openclaw.js';

// Perplexity Comet — agentic Chromium browser. Initial coverage: detection,
// version, profile-data permissions, and extension inventory (Comet ships
// hidden agentic extensions; SquareX 2025-11 showed the agentic MCP API could
// execute host commands). Connector/MCP configuration is serialized inside
// the Chromium profile (no documented standalone config file yet).
const APP_BUNDLE_PATH = '/Applications/Comet.app';

function profileDir(home: string, fs: FSProvider): string | undefined {
  if (fs.platform === 'darwin') {
    return join(home, 'Library', 'Application Support', 'Comet');
  }
  if (fs.platform === 'win32') {
    const localAppData = fs.getEnv('LOCALAPPDATA');
    if (localAppData) return join(localAppData, 'Perplexity', 'Comet', 'User Data');
  }
  return undefined;
}

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

export const cometAdapter: AgentAdapter = {
  agent: 'comet',
  displayName: 'Perplexity Comet',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    if (fs.platform !== 'darwin' && fs.platform !== 'win32') return [];

    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    const appExists = fs.platform === 'darwin' && (await fs.access(APP_BUNDLE_PATH));
    const version = appExists ? await readAppVersion(fs) : undefined;

    for (const { home, user } of userDirs) {
      const profile = profileDir(home, fs);
      const hasProfile = profile ? await fs.access(profile) : false;
      if (!appExists && !hasProfile) continue;

      const configFiles: ParsedConfig[] = [];

      installations.push({
        agent: 'comet',
        version,
        installDir: profile ?? APP_BUNDLE_PATH,
        configFiles,
        user: options?.allUsers ? user : undefined,
        appBundle: appExists ? APP_BUNDLE_PATH : undefined,
      });
    }

    return installations;
  },

  getConfigPaths(): string[] {
    return [];
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
    // Chromium profile: Cookies + Login Data hold session credentials
    // (encrypted with the OS keychain/DPAPI, but file exposure still matters).
    return [
      join(installDir, 'Default', 'Cookies'),
      join(installDir, 'Default', 'Login Data'),
    ];
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [],
      globPatterns: [
        '~/Library/Application Support/Comet/Default/Extensions/*/*/manifest.json',
      ],
      commands: [
        { id: 'comet-version', cmd: 'defaults', args: ['read', `${APP_BUNDLE_PATH}/Contents/Info.plist`, 'CFBundleShortVersionString'], timeout: 3000 },
        { id: 'comet-codesign', cmd: 'codesign', args: ['-dv', APP_BUNDLE_PATH], timeout: 5000 },
      ],
      // Session credentials and connector config — PC-001 checks permissions only
      metadataGlobPatterns: ['Cookies', 'Login Data', 'Web Data', 'Preferences']
        .map(f => `~/Library/Application Support/Comet/Default/${f}`),
      directoryListings: [
        '~/Library/Application Support/Comet',
        '~/Library/Application Support/Comet/Default',
        '~/Library/Application Support/Comet/Default/Extensions',
      ],
      envPrefixes: [],
      systemPaths: [APP_BUNDLE_PATH],
      systemDirListings: [],
    };
  },
};
