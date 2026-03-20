import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { nanoclawAdapter } from './nanoclaw.js';

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
  const pathSet = new Set(paths);
  mockAccess.mockImplementation(async (path) => {
    if (pathSet.has(path as string)) return undefined;
    throw new Error('ENOENT');
  });
}

function mockConfig(filePath: string, data: Record<string, unknown> = {}) {
  return {
    raw: JSON.stringify(data),
    format: 'json' as const,
    filePath,
    data,
  };
}

describe('NanoClaw adapter', () => {
  const home = process.env.HOME || '/home/testuser';
  const configDir = join(home, '.config', 'nanoclaw');
  const envPath = join(home, '.nanoclaw.env');

  beforeEach(() => {
    vi.resetAllMocks();
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
  });

  it('returns empty array when no configs found', async () => {
    setExistingPaths([]);
    const result = await nanoclawAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from .nanoclaw.env', async () => {
    setExistingPaths([envPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === envPath) {
        return mockConfig(envPath, { NANOCLAW_HOME: '/opt/nanoclaw', NANOCLAW_PORT: '8080' });
      }
      throw new Error('ENOENT');
    });

    const result = await nanoclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('nanoclaw');
    expect(result[0].installDir).toBe(configDir);
  });

  it('detects installation from config.json', async () => {
    const configPath = join(configDir, 'config.json');
    setExistingPaths([configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, { version: '2.0.0' });
      }
      throw new Error('ENOENT');
    });

    const result = await nanoclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].version).toBe('2.0.0');
  });

  it('detects mount-allowlist.json', async () => {
    const mountPath = join(configDir, 'mount-allowlist.json');
    setExistingPaths([mountPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === mountPath) {
        return mockConfig(mountPath, { allowedPaths: ['/tmp'] });
      }
      throw new Error('ENOENT');
    });

    const result = await nanoclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].configFiles).toHaveLength(1);
  });

  it('falls back to CLI version when config has no version', async () => {
    const configPath = join(configDir, 'config.json');
    setExistingPaths([configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, {});
      }
      throw new Error('ENOENT');
    });
    mockExecFileSync.mockReturnValue('nanoclaw 1.5.0\n' as any);

    const result = await nanoclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].version).toBe('1.5.0');
  });

  it('returns correct config paths', () => {
    const paths = nanoclawAdapter.getConfigPaths();
    expect(paths).toHaveLength(3);
    expect(paths).toContain(envPath);
    expect(paths).toContain(join(configDir, 'config.json'));
    expect(paths).toContain(join(configDir, 'mount-allowlist.json'));
  });

  it('returns skills dir relative to install dir', () => {
    const skillsDir = nanoclawAdapter.getSkillsDir(configDir);
    expect(skillsDir).toBe(join(configDir, 'skills'));
  });

  it('returns undefined gateway info', () => {
    const info = nanoclawAdapter.getGatewayInfo({});
    expect(info).toBeUndefined();
  });
});
