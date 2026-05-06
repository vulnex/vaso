import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { copilotCliAdapter } from './copilot-cli.js';

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

  it('parses JSONC config.json (with leading // comment header)', async () => {
    const configPath = join(copilotDir, 'config.json');
    setExistingPaths([copilotDir, configPath]);
    // mockReadFile is hoisted via vitest mock above
    const { readFile } = await import('node:fs/promises');
    vi.mocked(readFile).mockImplementation(async (p) => {
      if (p === configPath) {
        return `// User settings belong in settings.json.
// This file is managed automatically.
{
  "firstLaunchAt": "2026-04-29T10:30:05.040Z",
  "lastLoggedInUser": { "host": "https://github.com", "login": "vulnex" }
}`;
      }
      throw new Error('ENOENT');
    });

    const result = await copilotCliAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].configFiles).toHaveLength(1);
    expect(result[0].configFiles[0].data).toEqual({
      firstLaunchAt: '2026-04-29T10:30:05.040Z',
      lastLoggedInUser: { host: 'https://github.com', login: 'vulnex' },
    });
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

  it('credential paths surface config.json + settings.json', () => {
    const paths = copilotCliAdapter.getCredentialPaths!(copilotDir);
    expect(paths).toContain(join(copilotDir, 'config.json'));
    expect(paths).toContain(join(copilotDir, 'settings.json'));
  });
});
