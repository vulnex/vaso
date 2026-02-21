import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { nanobotAdapter } from './nanobot.js';

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

describe('Nanobot adapter', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
  });

  it('returns empty array when nothing found', async () => {
    setExistingPaths([]);
    const result = await nanobotAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from ~/.nanobot/config.json', async () => {
    const home = process.env.HOME || '/home/testuser';
    const nanobotDir = join(home, '.nanobot');
    const configPath = join(nanobotDir, 'config.json');

    setExistingPaths([configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, { host: '0.0.0.0', port: 18790 });
      }
      throw new Error('ENOENT');
    });

    const result = await nanobotAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('nanobot');
    expect(result[0].installDir).toBe(nanobotDir);
  });

  it('extracts gateway info', async () => {
    const home = process.env.HOME || '/home/testuser';
    const configPath = join(home, '.nanobot', 'config.json');

    setExistingPaths([configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, { host: '127.0.0.1', port: 18790 });
      }
      throw new Error('ENOENT');
    });

    const result = await nanobotAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].gateway).toEqual({ host: '127.0.0.1', port: 18790 });
  });

  it('returns correct skills dir (workspace/skills)', () => {
    expect(nanobotAdapter.getSkillsDir('/home/user/.nanobot'))
      .toBe(join('/home/user/.nanobot', 'workspace', 'skills'));
  });

  it('returns memory files', () => {
    const files = nanobotAdapter.getMemoryFiles!('/home/user/.nanobot');
    expect(files).toHaveLength(3);
    expect(files.some(f => f.includes('MEMORY.md'))).toBe(true);
    expect(files.some(f => f.includes('HEARTBEAT.md'))).toBe(true);
    expect(files.some(f => f.includes('SOUL.md'))).toBe(true);
  });

  it('returns credential paths', () => {
    const paths = nanobotAdapter.getCredentialPaths!('/home/user/.nanobot');
    expect(paths).toHaveLength(1);
    expect(paths[0]).toContain('config.json');
  });

  it('returns CLI command', () => {
    expect(nanobotAdapter.getCLICommand!()).toBe('nanobot');
  });

  it('defaults gateway host to 0.0.0.0 when not explicitly set', () => {
    const info = nanobotAdapter.getGatewayInfo({ port: 18790 });
    expect(info).toEqual({ host: '0.0.0.0', port: 18790 });
  });
});
