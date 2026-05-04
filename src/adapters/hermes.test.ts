import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { hermesAdapter } from './hermes.js';

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
    format: 'yaml' as const,
    filePath,
    data,
  };
}

describe('Hermes adapter', () => {
  const home = process.env.HOME || '/home/testuser';
  const hermesHome = join(home, '.hermes');

  beforeEach(() => {
    vi.resetAllMocks();
    delete process.env.HERMES_HOME;
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
  });

  it('returns empty array when .hermes dir does not exist', async () => {
    setExistingPaths([]);
    const result = await hermesAdapter.detect();
    expect(result).toEqual([]);
  });

  it('returns empty array when .hermes exists but has no config files', async () => {
    setExistingPaths([hermesHome]);
    mockLoadConfig.mockRejectedValue(new Error('ENOENT'));
    const result = await hermesAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from config.yaml', async () => {
    const configPath = join(hermesHome, 'config.yaml');
    setExistingPaths([hermesHome, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, {
          model: { default: 'anthropic/claude-opus-4.6' },
        });
      }
      throw new Error('ENOENT');
    });

    const result = await hermesAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('hermes');
    expect(result[0].installDir).toBe(hermesHome);
    expect(result[0].configFiles).toHaveLength(1);
  });

  it('detects installation from .env', async () => {
    const envPath = join(hermesHome, '.env');
    setExistingPaths([hermesHome, envPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === envPath) {
        return mockConfig(envPath, { OPENROUTER_API_KEY: 'sk-test' });
      }
      throw new Error('ENOENT');
    });

    const result = await hermesAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('hermes');
  });

  it('loads both config.yaml and .env when present', async () => {
    const configPath = join(hermesHome, 'config.yaml');
    const envPath = join(hermesHome, '.env');
    setExistingPaths([hermesHome, configPath, envPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) return mockConfig(configPath, { model: {} });
      if (path === envPath) return mockConfig(envPath, { OPENROUTER_API_KEY: 'sk-test' });
      throw new Error('ENOENT');
    });

    const result = await hermesAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].configFiles).toHaveLength(2);
  });

  it('extracts version from CLI', async () => {
    const configPath = join(hermesHome, 'config.yaml');
    setExistingPaths([hermesHome, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) return mockConfig(configPath, {});
      throw new Error('ENOENT');
    });
    mockExecFileSync.mockReturnValue('Hermes Agent v0.6.0\n' as any);

    const result = await hermesAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].version).toBe('0.6.0');
  });

  it('respects HERMES_HOME env var', async () => {
    const customHome = '/opt/hermes';
    process.env.HERMES_HOME = customHome;
    const configPath = join(customHome, 'config.yaml');
    setExistingPaths([customHome, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) return mockConfig(configPath, { model: {} });
      throw new Error('ENOENT');
    });

    const result = await hermesAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].installDir).toBe(customHome);
  });

  it('extracts gateway info from platforms.api_server config', () => {
    const info = hermesAdapter.getGatewayInfo({
      platforms: {
        api_server: { host: '0.0.0.0', port: 9000 },
      },
    });
    expect(info).toEqual({
      host: '0.0.0.0',
      port: 9000,
    });
  });

  it('returns default gateway info when platforms key exists but no api_server details', () => {
    const info = hermesAdapter.getGatewayInfo({ platforms: {} });
    expect(info).toEqual({
      host: '127.0.0.1',
      port: 8642,
    });
  });

  it('returns undefined gateway info when no platforms config', () => {
    const info = hermesAdapter.getGatewayInfo({});
    expect(info).toBeUndefined();
  });

  it('returns skills dir relative to install dir', () => {
    const skillsDir = hermesAdapter.getSkillsDir(hermesHome);
    expect(skillsDir).toBe(join(hermesHome, 'skills'));
  });

  it('returns correct config paths', () => {
    const paths = hermesAdapter.getConfigPaths();
    expect(paths).toHaveLength(3);
    expect(paths).toContain(join(hermesHome, 'cli-config.yaml'));
    expect(paths).toContain(join(hermesHome, 'config.yaml'));
    expect(paths).toContain(join(hermesHome, '.env'));
  });

  it('returns CLI command', () => {
    expect(hermesAdapter.getCLICommand!()).toBe('hermes');
  });

  it('returns probe manifest with expected structure', () => {
    const manifest = hermesAdapter.getProbeManifest!();
    expect(manifest.filePaths).toContain('~/.hermes/config.yaml');
    expect(manifest.filePaths).toContain('~/.hermes/.env');
    expect(manifest.globPatterns).toContain('~/.hermes/skills/**');
    expect(manifest.globPatterns).toContain('~/.hermes/optional-skills/**');
    expect(manifest.envPrefixes).toContain('HERMES_');
    expect(manifest.commands).toHaveLength(2);
  });

  it('returns credential paths', () => {
    const paths = hermesAdapter.getCredentialPaths!(hermesHome);
    expect(paths).toContain(join(hermesHome, '.env'));
    expect(paths).toContain(join(hermesHome, 'credentials.json'));
  });

  it('returns memory file paths', () => {
    const paths = hermesAdapter.getMemoryFiles!(hermesHome);
    expect(paths).toContain(join(hermesHome, 'memory'));
    expect(paths).toContain(join(hermesHome, 'conversations.db'));
  });
});
