import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { codexAdapter } from './codex.js';

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
  return {
    raw: '',
    format: 'toml' as const,
    filePath,
    data,
  };
}

describe('Codex adapter', () => {
  const home = process.env.HOME || '/home/testuser';
  const codexDir = join(home, '.codex');

  beforeEach(() => {
    vi.resetAllMocks();
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
  });

  it('returns empty array when nothing is present', async () => {
    setExistingPaths([]);
    const result = await codexAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from config.toml', async () => {
    const configPath = join(codexDir, 'config.toml');
    setExistingPaths([codexDir, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, { model: 'o4-mini', approval_policy: 'on-request' });
      }
      throw new Error('ENOENT');
    });

    const result = await codexAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('codex');
    expect(result[0].installDir).toBe(codexDir);
    expect(result[0].configFiles).toHaveLength(1);
  });

  it('reports installation when CLI binary exists but no config dir', async () => {
    setExistingPaths(['/usr/local/bin/codex']);
    const result = await codexAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe('/usr/local/bin/codex');
    expect(result[0].configFiles).toHaveLength(0);
  });

  it('does not detect a bare ~/.codex/ with no recognized configs and no CLI binary', async () => {
    setExistingPaths([codexDir]);
    const result = await codexAdapter.detect();
    expect(result).toEqual([]);
  });

  it('returns config paths under ~/.codex', () => {
    const paths = codexAdapter.getConfigPaths();
    expect(paths).toContain(join(codexDir, 'config.toml'));
    expect(paths).toContain(join(codexDir, 'auth.json'));
  });

  it('has no skills dir', () => {
    expect(codexAdapter.getSkillsDir(codexDir)).toBeUndefined();
  });

  it('has no gateway', () => {
    expect(codexAdapter.getGatewayInfo({})).toBeUndefined();
  });

  it('returns CLI command', () => {
    expect(codexAdapter.getCLICommand!()).toBe('codex');
  });

  it('returns probe manifest with expected paths', () => {
    const manifest = codexAdapter.getProbeManifest!();
    expect(manifest.filePaths).toContain('~/.codex/config.toml');
    expect(manifest.filePaths).toContain('~/.codex/auth.json');
    expect(manifest.envPrefixes).toContain('CODEX_');
    expect(manifest.envPrefixes).toContain('OPENAI_');
  });
});
