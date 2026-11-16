import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { copilotCliAdapter, COPILOT_PRIVATE_STORES } from './copilot-cli.js';

vi.mock('node:fs/promises', () => ({
  access: vi.fn(),
  readdir: vi.fn(),
  readFile: vi.fn(),
  stat: vi.fn(),
  realpath: vi.fn(),
}));

vi.mock('node:child_process', () => ({
  execFileSync: vi.fn(),
  execFile: vi.fn(),
}));

vi.mock('../core/config-loader.js', () => ({
  loadConfig: vi.fn(),
}));

import { access } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { loadConfig } from '../core/config-loader.js';

const mockAccess = vi.mocked(access);
const mockExecFileSync = vi.mocked(execFileSync);
const mockLoadConfig = vi.mocked(loadConfig);

function setExistingPaths(paths: string[]): void {
  const set = new Set(paths);
  mockAccess.mockImplementation(async (path) => {
    if (set.has(path as string)) return undefined;
    throw new Error('ENOENT');
  });
}

function mockConfig(filePath: string, data: Record<string, unknown> = {}) {
  return { raw: '', format: 'json' as const, filePath, data };
}

describe('GitHub Copilot CLI adapter', () => {
  const home = process.env.HOME || '/home/testuser';
  const copilotDir = join(home, '.copilot');

  beforeEach(() => {
    vi.resetAllMocks();
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
  });

  it('returns empty array when nothing is present', async () => {
    setExistingPaths([]);
    const result = await copilotCliAdapter.detect();
    expect(result).toEqual([]);
  });

  it('a config file that is there but not read still marks the install (its CONFIG-LOAD and GHC-001 belong to it)', async () => {
    // ~/.copilot linked into ~/.aws: config.json is not read on either side
    setExistingPaths([copilotDir, join(copilotDir, 'config.json')]);
    mockLoadConfig.mockRejectedValue(Object.assign(new Error('not read'), { omitted: 'sensitive' }));
    const result = await copilotCliAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].installDir).toBe(copilotDir);
    expect(result[0].configFiles).toEqual([]);
  });

  it('a bare ~/.copilot with no recognized config file is not an install', async () => {
    setExistingPaths([copilotDir, join(copilotDir, 'ide')]);
    expect(await copilotCliAdapter.detect()).toEqual([]);
  });

  it('does not treat a repo with .mcp.json as a Copilot install when Copilot is absent', async () => {
    // .mcp.json is also Claude Code's project file
    setExistingPaths([join(process.cwd(), '.mcp.json')]);
    mockLoadConfig.mockResolvedValue(mockConfig(join(process.cwd(), '.mcp.json'), { mcpServers: {} }));
    expect(await copilotCliAdapter.detect()).toEqual([]);
  });

  it('adds the project install next to an installed Copilot CLI', async () => {
    const settingsPath = join(copilotDir, 'settings.json');
    const mcpPath = join(process.cwd(), '.mcp.json');
    setExistingPaths([copilotDir, settingsPath, mcpPath]);
    mockLoadConfig.mockImplementation(async (path) => mockConfig(path as string, {}));
    const result = await copilotCliAdapter.detect();
    expect(result.map(i => i.profile)).toEqual([undefined, 'project']);
    expect(result[1].installDir).toBe(process.cwd());
  });

  it('detects installation from settings.json and extracts model', async () => {
    const settingsPath = join(copilotDir, 'settings.json');
    setExistingPaths([copilotDir, settingsPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === settingsPath) {
        return mockConfig(settingsPath, { model: 'claude-sonnet-4.5', updateChannel: 'stable' });
      }
      throw new Error('ENOENT');
    });

    const result = await copilotCliAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('copilot-cli');
    expect(result[0].installDir).toBe(copilotDir);
    expect(result[0].models).toEqual([{ id: 'claude-sonnet-4.5', provider: 'github-copilot' }]);
  });

  it('loads config.json through the shared (JSONC-tolerant) config loader', async () => {
    // config.json starts with a `// managed automatically` comment header;
    // loadConfig's lenient JSON parser handles it (config-loader.test.ts)
    const configPath = join(copilotDir, 'config.json');
    setExistingPaths([copilotDir, configPath]);
    const data = { firstLaunchAt: '2026-04-29T10:30:05.040Z', lastLoggedInUser: { host: 'https://github.com', login: 'vulnex' } };
    mockLoadConfig.mockImplementation(async (p) => {
      if (p === configPath) return mockConfig(configPath, data);
      throw new Error('ENOENT');
    });

    const result = await copilotCliAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].configFiles).toHaveLength(1);
    expect(result[0].configFiles[0].data).toEqual(data);
  });

  it('reports installation when CLI binary exists but no config dir', async () => {
    setExistingPaths(['/usr/local/bin/copilot']);
    const result = await copilotCliAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe('/usr/local/bin/copilot');
  });

  it('does not detect a bare ~/.copilot/ that is leftover IDE-extension state', async () => {
    // ~/.copilot/ exists but contains no recognized CLI config files (only
    // ide/ from the Copilot IDE extension or `gh copilot`) and no `copilot`
    // binary on PATH. This must not be reported as a CLI installation.
    setExistingPaths([copilotDir]);
    const result = await copilotCliAdapter.detect();
    expect(result).toEqual([]);
  });

  it('returns config paths under ~/.copilot', () => {
    const paths = copilotCliAdapter.getConfigPaths();
    expect(paths).toContain(join(copilotDir, 'settings.json'));
    expect(paths).toContain(join(copilotDir, 'config.json'));
    expect(paths).toContain(join(copilotDir, 'lsp-config.json'));
  });

  it('returns CLI command', () => {
    expect(copilotCliAdapter.getCLICommand!()).toBe('copilot');
  });

  it('probe manifest includes COPILOT_, GH_, GITHUB_ env prefixes', () => {
    const manifest = copilotCliAdapter.getProbeManifest!();
    expect(manifest.filePaths).toContain('~/.copilot/settings.json');
    expect(manifest.filePaths).toContain('~/.copilot/config.json');
    expect(manifest.envPrefixes).toContain('COPILOT_');
    expect(manifest.envPrefixes).toContain('GH_');
    expect(manifest.envPrefixes).toContain('GITHUB_');
  });

  it('probe manifest names every store GHC-001 judges as a private store', async () => {
    const { PRIVATE_DIRS } = await import('../checks/copilot-cli/ghc-001-dir-perms.js');
    const manifest = copilotCliAdapter.getProbeManifest!();
    expect([...COPILOT_PRIVATE_STORES].sort()).toEqual(PRIVATE_DIRS.map(d => d.dir).sort());
    expect(manifest.privateStores).toEqual(COPILOT_PRIVATE_STORES.map(d => `~/.copilot/${d}`));
    const { buildProbeManifest } = await import('../core/manifest-builder.js');
    const merged = buildProbeManifest([copilotCliAdapter]);
    expect(merged.privateStores).toEqual(expect.arrayContaining(['~/.copilot/session-state', '${COPILOT_HOME}/session-state']));
  });

  it('credential paths surface config.json + settings.json', () => {
    const paths = copilotCliAdapter.getCredentialPaths!(copilotDir);
    expect(paths).toContain(join(copilotDir, 'config.json'));
    expect(paths).toContain(join(copilotDir, 'settings.json'));
  });
});

describe('copilotHome', () => {
  const fsWith = (env: Record<string, string>, home = '/home/u') => ({ homedir: () => home, getEnv: (k: string) => env[k] }) as unknown as import('../core/fs-provider.js').FSProvider;
  it('honours $COPILOT_HOME for the scanning user', async () => {
    const { copilotHome } = await import('./copilot-cli.js');
    expect(copilotHome('/home/u', fsWith({}))).toBe('/home/u/.copilot');
    expect(copilotHome('/home/u', fsWith({ COPILOT_HOME: '/srv/cp' }))).toBe('/srv/cp');
    expect(copilotHome('/home/x', fsWith({ COPILOT_HOME: '/srv/cp' }))).toBe('/home/x/.copilot');
  });
});
