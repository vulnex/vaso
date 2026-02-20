import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { openclawAdapter, getUserHomeDirs } from './openclaw.js';

// Mock modules
vi.mock('node:fs/promises', () => ({
  access: vi.fn(),
  readdir: vi.fn(),
}));

vi.mock('node:child_process', () => ({
  execFileSync: vi.fn(),
}));

vi.mock('../core/config-loader.js', () => ({
  loadConfig: vi.fn(),
}));

import { access, readdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { loadConfig } from '../core/config-loader.js';

const mockAccess = vi.mocked(access);
const mockReaddir = vi.mocked(readdir);
const mockExecFileSync = vi.mocked(execFileSync);
const mockLoadConfig = vi.mocked(loadConfig);

// Track which paths "exist"
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

describe('OpenClaw adapter', () => {
  const originalEnv = process.env;
  const originalPlatform = process.platform;

  beforeEach(() => {
    vi.resetAllMocks();
    process.env = { ...originalEnv };
    delete process.env.OPENCLAW_HOME;
    delete process.env.OPENCLAW_PROFILE;
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
    mockReaddir.mockResolvedValue([]);
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('returns empty array when nothing found', async () => {
    setExistingPaths([]);
    const result = await openclawAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from ~/.openclaw config dir', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const configPath = join(openclawDir, 'openclaw.json');

    setExistingPaths([openclawDir, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, { version: '1.2.3' });
      }
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('openclaw');
    expect(result[0].installDir).toBe(openclawDir);
    expect(result[0].version).toBe('1.2.3');
    expect(result[0].configFiles).toHaveLength(1);
  });

  it('includes profile-specific directory when OPENCLAW_PROFILE is set', async () => {
    const home = process.env.HOME || '/home/testuser';
    process.env.OPENCLAW_PROFILE = 'work';
    const profileDir = join(home, '.openclaw-work');
    const configPath = join(profileDir, 'openclaw.json');

    setExistingPaths([profileDir, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, { version: '2.0.0' });
      }
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].installDir).toBe(profileDir);
    expect(result[0].profile).toBe('work');
  });

  it('detects CLI binary at system paths', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const configPath = join(openclawDir, 'config.json');
    const cliBinPath = '/usr/local/bin/openclaw';

    setExistingPaths([openclawDir, configPath, cliBinPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, {});
      }
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe(cliBinPath);
  });

  it('detects CLI binary via which fallback', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const configPath = join(openclawDir, 'openclaw.json');

    setExistingPaths([openclawDir, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, {});
      }
      throw new Error('ENOENT');
    });
    mockExecFileSync.mockReturnValue('/custom/path/openclaw\n' as any);

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe('/custom/path/openclaw');
  });

  it('detects macOS .app bundle', async () => {
    const home = process.env.HOME || '/home/testuser';
    const appPath = '/Applications/OpenClaw.app';

    // Only the .app exists, no config dirs
    setExistingPaths([appPath]);

    // Override platform to darwin for this test
    Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true });

    try {
      const result = await openclawAdapter.detect();
      expect(result).toHaveLength(1);
      expect(result[0].appBundle).toBe(appPath);
      expect(result[0].configFiles).toHaveLength(0);
    } finally {
      Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true });
    }
  });

  it('returns minimal installation when only CLI binary exists', async () => {
    const home = process.env.HOME || '/home/testuser';
    const cliBinPath = '/opt/homebrew/bin/openclaw';

    setExistingPaths([cliBinPath]);

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe(cliBinPath);
    expect(result[0].configFiles).toHaveLength(0);
    expect(result[0].installDir).toBe(join(home, '.openclaw'));
  });

  it('includes OPENCLAW_HOME in search dirs', async () => {
    const home = process.env.HOME || '/home/testuser';
    process.env.OPENCLAW_HOME = '/opt/openclaw';
    const configPath = join('/opt/openclaw', 'openclaw.json');

    setExistingPaths(['/opt/openclaw', configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, { version: '3.0.0' });
      }
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].installDir).toBe('/opt/openclaw');
    expect(result[0].version).toBe('3.0.0');
  });

  it('does not set user field when allUsers is not set', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const configPath = join(openclawDir, 'openclaw.json');

    setExistingPaths([openclawDir, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, {});
      }
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].user).toBeUndefined();
  });
});

describe('getUserHomeDirs', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('returns current user home when allUsers is false', async () => {
    const dirs = await getUserHomeDirs(false);
    expect(dirs).toHaveLength(1);
    expect(dirs[0].home).toBeTruthy();
  });

  it('returns current user home when allUsers is true but not root', async () => {
    // process.getuid() won't be 0 in test env
    const dirs = await getUserHomeDirs(true);
    expect(dirs).toHaveLength(1);
  });

  it('returns current user home when allUsers is undefined', async () => {
    const dirs = await getUserHomeDirs();
    expect(dirs).toHaveLength(1);
  });
});
