import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { picoclawAdapter } from './picoclaw.js';

vi.mock('node:fs/promises', () => ({
  access: vi.fn(),
}));

vi.mock('node:child_process', () => ({
  execFileSync: vi.fn(),
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

describe('PicoClaw adapter', () => {
  const home = process.env.HOME || '/home/testuser';
  const picoDir = join(home, '.picoclaw');
  const configPath = join(picoDir, 'config.json');
  const authPath = join(picoDir, 'auth.json');

  beforeEach(() => {
    vi.resetAllMocks();
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
  });

  it('returns empty array when no configs found', async () => {
    setExistingPaths([]);
    const result = await picoclawAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from config.json', async () => {
    setExistingPaths([configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, { version: '1.0.0' });
      }
      throw new Error('ENOENT');
    });

    const result = await picoclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('picoclaw');
    expect(result[0].installDir).toBe(picoDir);
    expect(result[0].version).toBe('1.0.0');
  });

  it('detects auth.json alongside config', async () => {
    setExistingPaths([configPath, authPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) return mockConfig(configPath, { version: '1.0.0' });
      if (path === authPath) return mockConfig(authPath, { auth: { mode: 'token' } });
      throw new Error('ENOENT');
    });

    const result = await picoclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].configFiles).toHaveLength(2);
  });

  it('merges config data for gateway extraction', async () => {
    setExistingPaths([configPath, authPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, {
          version: '1.0.0',
          gateway: { host: '0.0.0.0', port: 9090, tls: false },
        });
      }
      if (path === authPath) {
        return mockConfig(authPath, { auth: { mode: 'token' } });
      }
      throw new Error('ENOENT');
    });

    const result = await picoclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].gateway).toBeDefined();
    expect(result[0].gateway!.host).toBe('0.0.0.0');
    expect(result[0].gateway!.port).toBe(9090);
    expect(result[0].gateway!.authMode).toBe('token');
  });

  it('returns undefined gateway when no gateway key', async () => {
    setExistingPaths([configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) return mockConfig(configPath, { version: '1.0.0' });
      throw new Error('ENOENT');
    });

    const result = await picoclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].gateway).toBeUndefined();
  });

  it('falls back to CLI version when config has no version', async () => {
    setExistingPaths([configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) return mockConfig(configPath, {});
      throw new Error('ENOENT');
    });
    mockExecFileSync.mockReturnValue('picoclaw version 3.2.1\n' as any);

    const result = await picoclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].version).toBe('3.2.1');
  });

  it('returns correct config paths', () => {
    const paths = picoclawAdapter.getConfigPaths();
    expect(paths).toHaveLength(2);
    expect(paths).toContain(configPath);
    expect(paths).toContain(authPath);
  });

  it('returns skills dir relative to install dir', () => {
    const skillsDir = picoclawAdapter.getSkillsDir(picoDir);
    expect(skillsDir).toBe(join(picoDir, 'skills'));
  });
});
