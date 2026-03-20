import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { ironclawAdapter } from './ironclaw.js';

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

function mockConfig(filePath: string, data: Record<string, unknown> = {}) {
  return {
    raw: JSON.stringify(data),
    format: 'json' as const,
    filePath,
    data,
  };
}

describe('IronClaw adapter', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
  });

  it('returns empty array when nothing found', async () => {
    setExistingPaths([]);
    const result = await ironclawAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from ~/.ironclaw config dir', async () => {
    const home = process.env.HOME || '/home/testuser';
    const ironDir = join(home, '.ironclaw');
    const envPath = join(ironDir, '.env');
    const tomlPath = join(ironDir, 'config.toml');

    setExistingPaths([envPath, tomlPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === envPath) {
        return mockConfig(envPath, { GATEWAY_HOST: '0.0.0.0', GATEWAY_PORT: '8080' });
      }
      if (path === tomlPath) {
        return mockConfig(tomlPath, { gateway: { host: '0.0.0.0', port: 8080 } });
      }
      throw new Error('ENOENT');
    });

    const result = await ironclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('ironclaw');
    expect(result[0].installDir).toBe(ironDir);
    expect(result[0].configFiles).toHaveLength(2);
  });

  it('extracts gateway info from .env keys', async () => {
    const home = process.env.HOME || '/home/testuser';
    const ironDir = join(home, '.ironclaw');
    const envPath = join(ironDir, '.env');

    setExistingPaths([envPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === envPath) {
        return mockConfig(envPath, { GATEWAY_HOST: '127.0.0.1', GATEWAY_PORT: '9090' });
      }
      throw new Error('ENOENT');
    });

    const result = await ironclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].gateway).toEqual({
      host: '127.0.0.1',
      port: 9090,
    });
  });

  it('detects CLI binary at ~/.cargo/bin/ironclaw', async () => {
    const home = process.env.HOME || '/home/testuser';
    const cargoPath = join(home, '.cargo', 'bin', 'ironclaw');
    const envPath = join(home, '.ironclaw', '.env');

    setExistingPaths([envPath, cargoPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === envPath) return mockConfig(envPath, {});
      throw new Error('ENOENT');
    });

    const result = await ironclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe(cargoPath);
  });

  it('detects CLI binary via which fallback', async () => {
    const home = process.env.HOME || '/home/testuser';
    const envPath = join(home, '.ironclaw', '.env');

    setExistingPaths([envPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === envPath) return mockConfig(envPath, {});
      throw new Error('ENOENT');
    });
    mockExecFileSync.mockReturnValue('/usr/local/bin/ironclaw\n' as any);

    const result = await ironclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe('/usr/local/bin/ironclaw');
  });

  it('returns correct skills dir', () => {
    expect(ironclawAdapter.getSkillsDir('/home/user/.ironclaw'))
      .toBe(join('/home/user/.ironclaw', 'skills'));
  });

  it('returns correct config paths', () => {
    const paths = ironclawAdapter.getConfigPaths();
    expect(paths).toHaveLength(4);
    expect(paths.some(p => p.endsWith('.env'))).toBe(true);
    expect(paths.some(p => p.endsWith('config.toml'))).toBe(true);
  });

  it('returns credential paths', () => {
    const paths = ironclawAdapter.getCredentialPaths!('/home/user/.ironclaw');
    expect(paths).toHaveLength(3);
  });

  it('returns CLI command', () => {
    expect(ironclawAdapter.getCLICommand!()).toBe('ironclaw');
  });
});
