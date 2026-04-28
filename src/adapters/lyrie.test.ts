import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { lyrieAdapter } from './lyrie.js';

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
import { loadConfig } from '../core/config-loader.js';
import { execFileSync } from 'node:child_process';

const mockAccess = vi.mocked(access);
const mockLoadConfig = vi.mocked(loadConfig);
const mockExecFileSync = vi.mocked(execFileSync);

function setExistingPaths(paths: string[]): void {
  const pathSet = new Set(paths);
  mockAccess.mockImplementation(async (path) => {
    if (pathSet.has(path as string)) return undefined;
    throw new Error('ENOENT');
  });
}

function mockEnv(filePath: string, data: Record<string, unknown> = {}) {
  return {
    raw: Object.entries(data).map(([k, v]) => `${k}=${v}`).join('\n'),
    format: 'env' as const,
    filePath,
    data,
  };
}

describe('Lyrie adapter', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
  });

  it('returns empty array when nothing found', async () => {
    setExistingPaths([]);
    const result = await lyrieAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from ~/.lyrie/memory', async () => {
    const home = process.env.HOME || '/home/testuser';
    const memoryDir = join(home, '.lyrie', 'memory');
    const envPath = join(home, '.lyrie', '.env');

    setExistingPaths([memoryDir, envPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === envPath) return mockEnv(envPath, { LYRIE_SHIELD_MODE: 'active' });
      throw new Error('ENOENT');
    });

    const result = await lyrieAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('lyrie');
    expect(result[0].installDir).toBe(join(home, '.lyrie'));
    expect(result[0].configFiles).toHaveLength(1);
  });

  it('detects installation from pairing.json alone', async () => {
    const home = process.env.HOME || '/home/testuser';
    const pairingPath = join(home, '.lyrie', 'pairing.json');

    setExistingPaths([pairingPath]);
    mockLoadConfig.mockImplementation(async () => { throw new Error('ENOENT'); });

    const result = await lyrieAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('lyrie');
  });

  it('extracts WebChat gateway info when port is set', async () => {
    const home = process.env.HOME || '/home/testuser';
    const memoryDir = join(home, '.lyrie', 'memory');
    const envPath = join(home, '.lyrie', '.env');

    setExistingPaths([memoryDir, envPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === envPath) {
        return mockEnv(envPath, {
          LYRIE_WEBCHAT_HOST: '0.0.0.0',
          LYRIE_WEBCHAT_PORT: '8765',
        });
      }
      throw new Error('ENOENT');
    });

    const result = await lyrieAdapter.detect();
    expect(result[0].gateway).toEqual({ host: '0.0.0.0', port: 8765 });
  });

  it('returns no gateway info when WebChat not configured', async () => {
    const home = process.env.HOME || '/home/testuser';
    const memoryDir = join(home, '.lyrie', 'memory');

    setExistingPaths([memoryDir]);
    mockLoadConfig.mockImplementation(async () => { throw new Error('ENOENT'); });

    const result = await lyrieAdapter.detect();
    expect(result[0].gateway).toBeUndefined();
  });

  it('detects CLI binary via which fallback', async () => {
    setExistingPaths([]);
    mockExecFileSync.mockReturnValue('/usr/local/bin/lyrie\n' as any);

    const result = await lyrieAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe('/usr/local/bin/lyrie');
  });

  it('returns correct skills dir', () => {
    expect(lyrieAdapter.getSkillsDir('/home/user/.lyrie'))
      .toBe(join('/home/user/.lyrie', 'skills'));
  });

  it('returns correct config paths', () => {
    const paths = lyrieAdapter.getConfigPaths();
    expect(paths.some(p => p.endsWith('.env'))).toBe(true);
  });

  it('returns memory files', () => {
    const files = lyrieAdapter.getMemoryFiles!('/home/user/.lyrie');
    expect(files).toContain('/home/user/.lyrie/memory/lyrie-memory.db');
    expect(files).toContain('/home/user/.lyrie/edits.json');
    expect(files).toContain('/home/user/.lyrie/pairing.json');
  });

  it('returns CLI command', () => {
    expect(lyrieAdapter.getCLICommand!()).toBe('lyrie');
  });

  it('zone graph has 5 zones with shield-bypass and pairing-bypass inversions', () => {
    const graph = lyrieAdapter.getZoneGraph!();
    expect(graph.zones).toHaveLength(5);
    const inversions = graph.edges.filter(e => e.triggerCheckIds && e.triggerCheckIds.length > 0);
    expect(inversions).toHaveLength(2);
    expect(inversions.map(e => e.label)).toEqual(
      expect.arrayContaining(['shield bypass', 'DM pairing bypass']),
    );
  });

  it('probe manifest covers memory archive, migrations, and channel env prefixes', () => {
    const manifest = lyrieAdapter.getProbeManifest!();
    expect(manifest.filePaths).toContain('~/.lyrie/.env');
    expect(manifest.globPatterns).toContain('~/.lyrie/memory/archive/*.db');
    expect(manifest.globPatterns).toContain('~/.lyrie/migrations/*.json');
    expect(manifest.envPrefixes).toContain('LYRIE_');
    expect(manifest.envPrefixes).toContain('TELEGRAM_');
    expect(manifest.envPrefixes).toContain('DAYTONA_');
    expect(manifest.envPrefixes).toContain('MODAL_');
  });
});
