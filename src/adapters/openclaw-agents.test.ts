import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { openclawAdapter } from './openclaw.js';

// Mock modules
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

import { access, readdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { loadConfig } from '../core/config-loader.js';
import type { Dirent } from 'node:fs';

const mockAccess = vi.mocked(access);
const mockReaddir = vi.mocked(readdir);
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

function mockDirent(name: string, isDir: boolean): Dirent {
  return {
    name,
    isDirectory: () => isDir,
    isFile: () => !isDir,
    isBlockDevice: () => false,
    isCharacterDevice: () => false,
    isFIFO: () => false,
    isSocket: () => false,
    isSymbolicLink: () => false,
    parentPath: '',
    path: '',
  } as Dirent;
}

describe('OpenClaw per-agent discovery', () => {
  const originalEnv = process.env;

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

  it('does not report agents/<id>/agent.{yaml,json} as a sub-agent install (OpenClaw never reads them)', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const agentsDir = join(openclawDir, 'agents');
    const researcherDir = join(agentsDir, 'researcher');
    const globalConfigPath = join(openclawDir, 'openclaw.json');
    const researcherConfigPath = join(researcherDir, 'agent.yaml');

    setExistingPaths([openclawDir, globalConfigPath, agentsDir, researcherDir]);
    mockReaddir.mockImplementation((async (dir: unknown) => (dir === agentsDir ? [mockDirent('researcher', true)] : [])) as any);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === globalConfigPath) return mockConfig(globalConfigPath, { gateway: { bind: 'loopback' } });
      if (path === researcherConfigPath) return mockConfig(researcherConfigPath, { gateway: { bind: 'lan' } });
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agentName).toBeUndefined();
    expect(result[0].configFiles.map(c => c.filePath)).not.toContain(researcherConfigPath);
    expect(mockLoadConfig).not.toHaveBeenCalledWith(researcherConfigPath, expect.anything());
  });

  it('emits only global installation when no agents/ dir exists', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const configPath = join(openclawDir, 'openclaw.json');

    setExistingPaths([openclawDir, configPath]);

    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, { version: '1.0.0' });
      }
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agentName).toBeUndefined();
    expect(result[0].installDir).toBe(openclawDir);
  });

  it('does not report a 2026.x per-agent state dir (agents/main/agent/) as a sub-agent', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const agentsDir = join(openclawDir, 'agents');
    const configPath = join(openclawDir, 'openclaw.json');

    setExistingPaths([openclawDir, configPath, agentsDir, join(agentsDir, 'main')]);
    mockReaddir.mockImplementation((async (dir: unknown) => (dir === agentsDir ? [mockDirent('main', true)] : [])) as any);
    // agents/main/agent is a directory (auth-profiles.json, …), not a config file
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) return mockConfig(configPath, { gateway: { bind: 'loopback' } });
      throw Object.assign(new Error('EISDIR'), { code: 'EISDIR' });
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agentName).toBeUndefined();
  });

  it('skips non-directory entries in agents/', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const agentsDir = join(openclawDir, 'agents');
    const configPath = join(openclawDir, 'openclaw.json');

    setExistingPaths([openclawDir, configPath, agentsDir]);

    // Keyed by path: other lookups (e.g. nvm version dirs) list nothing
    mockReaddir.mockImplementation((async (dir: unknown) => (dir === agentsDir ? [
        mockDirent('README.md', false),
        mockDirent('.DS_Store', false),
      ] : [])) as any);

    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) return mockConfig(configPath, {});
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    // Only global installation, no sub-agents from non-directory entries
    expect(result).toHaveLength(1);
    expect(result[0].agentName).toBeUndefined();
  });
});
