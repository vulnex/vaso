import { join } from 'node:path';
import type { AgentAdapter, DetectOptions } from './adapter.js';
import type { AgentInstallation, GatewayInfo, ModelRef, ParsedConfig, ZoneGraph } from '../core/types.js';
import type { ProbeManifest } from '../core/snapshot-types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { loadConfig } from '../core/config-loader.js';
import { getUserHomeDirs } from './openclaw.js';

const CONFIG_FILE = 'claude_desktop_config.json';
const EXTENSIONS_DIR_NAME = 'Claude Extensions';
const APP_BUNDLE_PATH = '/Applications/Claude.app';
const LOCAL_STORAGE_LEVELDB = ['Local Storage', 'leveldb'];
const SELECTOR_KEY = 'model-selector-local';
const MODEL_ID_RE = /claude-(?:opus|sonnet|haiku)-\d+(?:-\d+)?(?:\[\d+m\])?/;

/**
 * Resolve the per-user Claude Desktop config directory.
 * macOS: ~/Library/Application Support/Claude
 * Windows: %APPDATA%\Claude
 * Linux: no native app — return undefined so detect() bails cleanly.
 */
function getDesktopConfigDir(home: string, fs: FSProvider): string | undefined {
  if (fs.platform === 'darwin') {
    return join(home, 'Library', 'Application Support', 'Claude');
  }
  if (fs.platform === 'win32') {
    const appData = fs.getEnv?.('APPDATA');
    if (appData) return join(appData, 'Claude');
    return join(home, 'AppData', 'Roaming', 'Claude');
  }
  return undefined;
}

async function findAppBundle(fs: FSProvider): Promise<string | undefined> {
  if (fs.platform === 'darwin' && (await fs.access(APP_BUNDLE_PATH))) {
    return APP_BUNDLE_PATH;
  }
  return undefined;
}

async function readAppVersion(fs: FSProvider): Promise<string | undefined> {
  if (fs.platform !== 'darwin') return undefined;
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

/**
 * Recover the active model id from Claude Desktop's Chromium Local Storage.
 * The picker writes the user's selection to a `model-selector-local_<acct>`
 * key in `<installDir>/Local Storage/leveldb/`. The store is binary LevelDB
 * (snappy-compressed SSTables), so we don't try to decode the format —
 * instead we scan the .ldb / .log files for the ASCII key anchor and pull
 * out the first well-formed Claude model id within the following window.
 *
 * Works over both local and snapshot transports because the bytes we care
 * about are pure ASCII: Go's JSON encoder coerces invalid UTF-8 in file
 * content to U+FFFD on the wire, and Node's utf-8 `readFile` does the same
 * on the local side, but neither touches valid ASCII. The ~256-char window
 * is a heuristic — if Local Storage gets large enough that the relevant
 * block is snappy-compressed, the value disappears entirely from both
 * transports and we return undefined.
 */
async function readLocalStorageModel(installDir: string, fs: FSProvider): Promise<string | undefined> {
  const ldbDir = join(installDir, ...LOCAL_STORAGE_LEVELDB);
  if (!(await fs.access(ldbDir))) return undefined;

  let entries;
  try {
    entries = await fs.readdirEntries(ldbDir);
  } catch {
    return undefined;
  }

  const files = entries
    .filter(e => e.isFile && (e.name.endsWith('.ldb') || e.name.endsWith('.log')))
    .map(e => join(ldbDir, e.name));

  for (const f of files) {
    try {
      const text = await fs.readFile(f);
      const keyIdx = text.indexOf(SELECTOR_KEY);
      if (keyIdx < 0) continue;
      const window = text.slice(keyIdx, keyIdx + 256);
      const match = MODEL_ID_RE.exec(window);
      if (match) return match[0];
    } catch {}
  }
  return undefined;
}

async function loadDesktopConfig(dir: string, fs: FSProvider): Promise<ParsedConfig[]> {
  const configFiles: ParsedConfig[] = [];
  const filePath = join(dir, CONFIG_FILE);
  if (!(await fs.access(filePath))) return configFiles;
  try {
    configFiles.push(await loadConfig(filePath, fs));
  } catch {}
  return configFiles;
}

export const claudeDesktopAdapter: AgentAdapter = {
  agent: 'claude-desktop',
  displayName: 'Claude Desktop',

  async detect(options?: DetectOptions): Promise<AgentInstallation[]> {
    const fs = options?.fs ?? new LocalFSProvider();
    const userDirs = await getUserHomeDirs(options?.allUsers, fs);
    const installations: AgentInstallation[] = [];

    const appBundle = await findAppBundle(fs);
    const version = appBundle ? await readAppVersion(fs) : undefined;

    for (const { home, user } of userDirs) {
      const configDir = getDesktopConfigDir(home, fs);
      if (!configDir) continue;

      const hasConfigDir = await fs.access(configDir);
      if (!hasConfigDir && !appBundle) continue;

      const configFiles = hasConfigDir ? await loadDesktopConfig(configDir, fs) : [];
      let models = this.getModels?.(configFiles, fs) as ModelRef[] | undefined;
      if (!models || models.length === 0) {
        const inferredId = hasConfigDir ? await readLocalStorageModel(configDir, fs) : undefined;
        if (inferredId) models = [{ id: inferredId, provider: 'anthropic', via: 'cowork local-storage' }];
      }

      installations.push({
        agent: 'claude-desktop',
        version,
        installDir: configDir,
        configFiles,
        models,
        user: options?.allUsers ? user : undefined,
        appBundle,
      });
    }

    return installations;
  },

  getConfigPaths(): string[] {
    const fs = new LocalFSProvider();
    const dir = getDesktopConfigDir(fs.homedir(), fs);
    return dir ? [join(dir, CONFIG_FILE)] : [];
  },

  getSkillsDir(installDir: string): string | undefined {
    // Claude Desktop's "skills"-equivalent surface is the Extensions directory
    // (.mcpb bundles). Return the path so SKL-* checks can scan packaged
    // extension code if/when that's wired up; the dir may not exist on a
    // fresh install.
    return join(installDir, EXTENSIONS_DIR_NAME);
  },

  getGatewayInfo(_config: Record<string, unknown>): GatewayInfo | undefined {
    return undefined;
  },

  getModels(configs: ParsedConfig[]): ModelRef[] {
    // Claude Desktop persists very little about the active model — the picker
    // lives in app state, not the JSON config. Surface only an explicit
    // top-level `model` field if a user has set one (rare but supported).
    for (const file of configs) {
      const id = file.data?.model as string | undefined;
      if (id) return [{ id, provider: 'anthropic' }];
    }
    return [];
  },

  getMemoryFiles(): string[] {
    return [];
  },

  getCredentialPaths(installDir: string): string[] {
    return [join(installDir, CONFIG_FILE)];
  },

  getProbeManifest(): ProbeManifest {
    return {
      filePaths: [
        '~/Library/Application Support/Claude/claude_desktop_config.json',
      ],
      globPatterns: [
        '~/Library/Application Support/Claude/Claude Extensions/**',
        // Chromium Local Storage SSTables — read for the active-model
        // sticky-selector value. Binary content gets U+FFFD-substituted in
        // the JSON snapshot, but the ASCII anchor key and the model id
        // survive intact, which is all readLocalStorageModel needs.
        '~/Library/Application Support/Claude/Local Storage/leveldb/*.ldb',
        '~/Library/Application Support/Claude/Local Storage/leveldb/*.log',
      ],
      commands: [
        { id: 'claude-desktop-version', cmd: 'defaults', args: ['read', `${APP_BUNDLE_PATH}/Contents/Info.plist`, 'CFBundleShortVersionString'], timeout: 3000 },
      ],
      directoryListings: [
        '~/Library/Application Support/Claude',
        '~/Library/Application Support/Claude/Claude Extensions',
        '~/Library/Application Support/Claude/Local Storage/leveldb',
      ],
      envPrefixes: ['CLAUDE_', 'ANTHROPIC_'],
      systemPaths: [APP_BUNDLE_PATH],
      systemDirListings: [],
    };
  },

  // Privilege gradient: untrusted network → MCP transport / extensions →
  // tool approval (alwaysApprove + per-tool prompts) → connected folders on
  // host. Inversion fires when always-approve is broad or unsigned MCPB
  // extensions are installed, letting prompt-injected tool calls reach the
  // host filesystem without confirmation.
  getZoneGraph(): ZoneGraph {
    return {
      zones: [
        { id: 'net', label: 'Network / Cloud', trustLevel: 0 },
        { id: 'mcp', label: 'MCP / Extensions', trustLevel: 1 },
        { id: 'approval', label: 'Approval Layer', trustLevel: 2 },
        { id: 'host', label: 'Connected Folders', trustLevel: 3 },
      ],
      components: [
        { id: 'inbound', label: 'Network / Remote MCP', zone: 'net' },
        {
          id: 'mcp-transport',
          label: 'MCP Servers + .mcpb Extensions',
          zone: 'mcp',
          guardCheckIds: ['CD-003', 'CD-004', 'CD-005'],
        },
        {
          id: 'approval',
          label: 'Tool Approval',
          zone: 'approval',
          guardCheckIds: ['CD-006', 'CD-009'],
        },
        {
          id: 'fs',
          label: 'Connected Folders',
          zone: 'host',
          guardCheckIds: ['CD-001', 'CD-002', 'CD-007'],
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
          triggerCheckIds: ['CD-005', 'CD-006'],
        },
      ],
    };
  },
};
