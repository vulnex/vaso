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

  it('returns config paths under ~/.codex, never the auth.json token store', () => {
    const paths = codexAdapter.getConfigPaths();
    expect(paths).toContain(join(codexDir, 'config.toml'));
    expect(paths).not.toContain(join(codexDir, 'auth.json'));
  });

  it('detects a signed-in install with no config.toml or binary, without parsing auth.json', async () => {
    setExistingPaths([codexDir, join(codexDir, 'auth.json')]);
    const result = await codexAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].configFiles).toEqual([]);
    expect(mockLoadConfig).not.toHaveBeenCalledWith(join(codexDir, 'auth.json'), expect.anything());
  });

  it('keeps user skills in <CODEX_HOME>/skills', () => {
    expect(codexAdapter.getSkillsDir(codexDir)).toBe(join(codexDir, 'skills'));
  });

  it('has no gateway', () => {
    expect(codexAdapter.getGatewayInfo({})).toBeUndefined();
  });

  it('loads $CODEX_HOME/<name>.config.toml profile files and trusted projects\' .codex layer', async () => {
    const configPath = join(codexDir, 'config.toml');
    const profilePath = join(codexDir, 'yolo.config.toml');
    const project = '/work/proj';
    const projectConfig = join(project, '.codex', 'config.toml');
    setExistingPaths([codexDir, configPath, profilePath, join(project, '.codex'), projectConfig]);
    const { readdir } = await import('node:fs/promises');
    vi.mocked(readdir).mockImplementation((async (p: string) =>
      (p === codexDir ? ['config.toml', 'yolo.config.toml', 'auth.json'] : [])) as any);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) return mockConfig(configPath, { projects: { [project]: { trust_level: 'trusted' }, '/work/other': { trust_level: 'untrusted' } } });
      if (path === profilePath) return mockConfig(profilePath, { approval_policy: 'never' });
      if (path === projectConfig) return mockConfig(projectConfig, { approval_policy: 'never' });
      throw new Error('ENOENT');
    });

    const result = await codexAdapter.detect();
    const user = result.find(r => !r.profile);
    expect(user!.configFiles.map(c => c.filePath)).toEqual([configPath, profilePath]);
    const proj = result.find(r => r.profile === 'project');
    expect(proj?.installDir).toBe(join(project, '.codex'));
    expect(proj?.configFiles.map(c => c.filePath)).toEqual([projectConfig]);
    expect(result).toHaveLength(2);
  });

  it('returns CLI command', () => {
    expect(codexAdapter.getCLICommand!()).toBe('codex');
  });

  it('returns probe manifest with expected paths', () => {
    const manifest = codexAdapter.getProbeManifest!();
    expect(manifest.filePaths).toContain('~/.codex/config.toml');
    // OAuth tokens: permissions only (CDX-003), never shipped off the host
    expect(manifest.filePaths).not.toContain('~/.codex/auth.json');
    expect(manifest.metadataGlobPatterns).toContain('~/.codex/auth.json');
    expect(manifest.envPrefixes).toContain('CODEX_');
    expect(manifest.envPrefixes).toContain('OPENAI_');
  });
});

describe('codexHome', () => {
  const fsWith = (env: Record<string, string>, home = '/home/u') => ({ homedir: () => home, getEnv: (k: string) => env[k] }) as unknown as import('../core/fs-provider.js').FSProvider;
  it('honours $CODEX_HOME for the scanning user only', async () => {
    const { codexHome } = await import('./codex.js');
    expect(codexHome('/home/u', fsWith({}))).toBe('/home/u/.codex');
    expect(codexHome('/home/u', fsWith({ CODEX_HOME: '/srv/codex' }))).toBe('/srv/codex');
    expect(codexHome('/home/u', fsWith({ CODEX_HOME: '~/alt' }))).toBe('/home/u/alt');
    expect(codexHome('/home/other', fsWith({ CODEX_HOME: '/srv/codex' }))).toBe('/home/other/.codex');
  });
});
