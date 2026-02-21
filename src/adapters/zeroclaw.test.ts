import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { zeroclawAdapter } from './zeroclaw.js';

vi.mock('node:fs/promises', () => ({
  access: vi.fn(),
}));

vi.mock('node:child_process', () => ({
  execFileSync: vi.fn(),
}));

vi.mock('../core/config-loader.js', () => ({
  loadConfig: vi.fn(),
}));

vi.mock('../core/utils.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../core/utils.js')>();
  return {
    ...actual,
    pathExists: vi.fn(),
    getNestedValue: (await importOriginal<typeof import('../core/utils.js')>()).getNestedValue,
  };
});

import { loadConfig } from '../core/config-loader.js';
import { pathExists } from '../core/utils.js';
import { execFileSync } from 'node:child_process';

const mockPathExists = vi.mocked(pathExists);
const mockLoadConfig = vi.mocked(loadConfig);
const mockExecFileSync = vi.mocked(execFileSync);

function setExistingPaths(paths: string[]): void {
  const pathSet = new Set(paths);
  mockPathExists.mockImplementation(async (path) => pathSet.has(path));
}

function mockConfig(filePath: string, data: Record<string, unknown> = {}) {
  return {
    raw: JSON.stringify(data),
    format: 'json' as const,
    filePath,
    data,
  };
}

describe('ZeroClaw adapter', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
  });

  it('returns empty array when nothing found', async () => {
    setExistingPaths([]);
    const result = await zeroclawAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from ~/.zeroclaw config dir', async () => {
    const home = process.env.HOME || '/home/testuser';
    const zeroDir = join(home, '.zeroclaw');
    const tomlPath = join(zeroDir, 'config.toml');

    setExistingPaths([tomlPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === tomlPath) {
        return mockConfig(tomlPath, { server: { host: '127.0.0.1', port: 3000 } });
      }
      throw new Error('ENOENT');
    });

    const result = await zeroclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('zeroclaw');
    expect(result[0].installDir).toBe(zeroDir);
  });

  it('extracts gateway info from [server] section', async () => {
    const home = process.env.HOME || '/home/testuser';
    const tomlPath = join(home, '.zeroclaw', 'config.toml');

    setExistingPaths([tomlPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === tomlPath) {
        return mockConfig(tomlPath, { server: { host: '[::]', port: 3000 } });
      }
      throw new Error('ENOENT');
    });

    const result = await zeroclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].gateway).toEqual({ host: '[::]', port: 3000 });
  });

  it('extracts gateway info from [gateway] section as fallback', () => {
    const info = zeroclawAdapter.getGatewayInfo({ gateway: { host: '0.0.0.0', port: 4000 } });
    expect(info).toEqual({ host: '0.0.0.0', port: 4000 });
  });

  it('detects CLI binary at ~/.cargo/bin/zeroclaw', async () => {
    const home = process.env.HOME || '/home/testuser';
    const cargoPath = join(home, '.cargo', 'bin', 'zeroclaw');
    const tomlPath = join(home, '.zeroclaw', 'config.toml');

    setExistingPaths([tomlPath, cargoPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === tomlPath) return mockConfig(tomlPath, {});
      throw new Error('ENOENT');
    });

    const result = await zeroclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe(cargoPath);
  });

  it('returns correct skills dir (workspace/skills)', () => {
    expect(zeroclawAdapter.getSkillsDir('/home/user/.zeroclaw'))
      .toBe(join('/home/user/.zeroclaw', 'workspace', 'skills'));
  });

  it('returns credential paths including .secret_key', () => {
    const paths = zeroclawAdapter.getCredentialPaths!('/home/user/.zeroclaw');
    expect(paths).toHaveLength(3);
    expect(paths.some(p => p.endsWith('.secret_key'))).toBe(true);
    expect(paths.some(p => p.endsWith('config.toml'))).toBe(true);
    expect(paths.some(p => p.endsWith('auth-profiles.json'))).toBe(true);
  });

  it('returns CLI command', () => {
    expect(zeroclawAdapter.getCLICommand!()).toBe('zeroclaw');
  });
});
