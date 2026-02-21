import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { openclawAdapter } from './openclaw.js';

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

  it('discovers sub-agents under agents/ directory', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const agentsDir = join(openclawDir, 'agents');
    const researcherDir = join(agentsDir, 'researcher');
    const coderDir = join(agentsDir, 'coder');
    const sharedSkillsDir = join(openclawDir, 'skills');
    const researcherSkillsDir = join(researcherDir, 'skills');

    const globalConfigPath = join(openclawDir, 'config.yaml');
    const researcherConfigPath = join(researcherDir, 'agent.yaml');
    const coderConfigPath = join(coderDir, 'agent.yaml');

    setExistingPaths([
      openclawDir,
      globalConfigPath,
      agentsDir,
      researcherDir,
      coderDir,
      sharedSkillsDir,
      researcherSkillsDir,
    ]);

    // readdir is called for the agents/ directory (getUserHomeDirs doesn't call readdir when not root)
    mockReaddir
      .mockResolvedValueOnce([
        mockDirent('researcher', true),
        mockDirent('coder', true),
      ] as any);

    mockLoadConfig.mockImplementation(async (path) => {
      if (path === globalConfigPath) {
        return mockConfig(globalConfigPath, {
          sandbox: true,
          gateway: { host: '127.0.0.1', port: 8080 },
        });
      }
      if (path === researcherConfigPath) {
        return mockConfig(researcherConfigPath, {
          sandbox: false,
          model: 'gpt-4',
        });
      }
      if (path === coderConfigPath) {
        return mockConfig(coderConfigPath, {
          model: 'claude',
          tools: ['code_exec'],
        });
      }
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();

    // Should return 3 installations: 1 global + 2 sub-agents
    expect(result).toHaveLength(3);

    // Global installation
    expect(result[0].agentName).toBeUndefined();
    expect(result[0].installDir).toBe(openclawDir);

    // Researcher sub-agent
    const researcher = result.find(i => i.agentName === 'researcher');
    expect(researcher).toBeDefined();
    expect(researcher!.installDir).toBe(researcherDir);
    expect(researcher!.agent).toBe('openclaw');

    // Verify config merging: agent overrides global sandbox
    const researcherConfigs = researcher!.configFiles;
    // Should include both global and agent-specific configs
    expect(researcherConfigs.length).toBeGreaterThan(1);

    // Verify skillsDirs includes both shared and per-agent
    expect(researcher!.skillsDirs).toContain(sharedSkillsDir);
    expect(researcher!.skillsDirs).toContain(researcherSkillsDir);
    // skillsDir should be the per-agent one (last in list)
    expect(researcher!.skillsDir).toBe(researcherSkillsDir);

    // Coder sub-agent
    const coder = result.find(i => i.agentName === 'coder');
    expect(coder).toBeDefined();
    expect(coder!.installDir).toBe(coderDir);
    // Coder has no skills/ dir so skillsDirs should only have shared
    expect(coder!.skillsDirs).toContain(sharedSkillsDir);
    expect(coder!.skillsDirs).not.toContain(join(coderDir, 'skills'));
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

  it('sets agentName correctly for each sub-agent', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const agentsDir = join(openclawDir, 'agents');
    const assistantDir = join(agentsDir, 'assistant');
    const configPath = join(openclawDir, 'config.yaml');
    const agentConfigPath = join(assistantDir, 'agent.yaml');

    setExistingPaths([openclawDir, configPath, agentsDir, assistantDir]);

    mockReaddir
      .mockResolvedValueOnce([mockDirent('assistant', true)] as any);

    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) return mockConfig(configPath, { sandbox: true });
      if (path === agentConfigPath) return mockConfig(agentConfigPath, { name: 'assistant' });
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(2);
    expect(result[1].agentName).toBe('assistant');
  });

  it('inherits cliBinary and appBundle from parent installation', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const agentsDir = join(openclawDir, 'agents');
    const agentDir = join(agentsDir, 'test-agent');
    const configPath = join(openclawDir, 'config.yaml');
    const cliBinPath = '/usr/local/bin/openclaw';

    setExistingPaths([openclawDir, configPath, agentsDir, agentDir, cliBinPath]);

    mockReaddir
      .mockResolvedValueOnce([mockDirent('test-agent', true)] as any);

    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) return mockConfig(configPath, {});
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    const subAgent = result.find(i => i.agentName === 'test-agent');
    expect(subAgent).toBeDefined();
    expect(subAgent!.cliBinary).toBe(cliBinPath);
  });

  it('skips non-directory entries in agents/', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const agentsDir = join(openclawDir, 'agents');
    const configPath = join(openclawDir, 'config.yaml');

    setExistingPaths([openclawDir, configPath, agentsDir]);

    mockReaddir
      .mockResolvedValueOnce([
        mockDirent('README.md', false),
        mockDirent('.DS_Store', false),
      ] as any);

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
