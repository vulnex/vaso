import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { claudeCodeAdapter } from './claude-code.js';

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
  const set = new Set(paths);
  mockAccess.mockImplementation(async (path) => {
    if (set.has(path as string)) return undefined;
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

describe('Claude Code adapter', () => {
  const home = process.env.HOME || '/home/testuser';
  const claudeDir = join(home, '.claude');

  beforeEach(() => {
    vi.resetAllMocks();
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
  });

  it('returns empty array when no .claude dir, no .claude.json, and no CLI binary', async () => {
    setExistingPaths([]);
    const result = await claudeCodeAdapter.detect();
    // May still return a project-level installation if cwd has .claude/, but in a clean cwd it should be []
    const userInstalls = result.filter(r => !r.profile);
    expect(userInstalls).toEqual([]);
  });

  it('detects installation from settings.json', async () => {
    const settingsPath = join(claudeDir, 'settings.json');
    setExistingPaths([claudeDir, settingsPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === settingsPath) {
        return mockConfig(settingsPath, { model: 'claude-opus-4.7' });
      }
      throw new Error('ENOENT');
    });

    const result = await claudeCodeAdapter.detect();
    const userInstall = result.find(r => !r.profile);
    expect(userInstall).toBeDefined();
    expect(userInstall!.agent).toBe('claude-code');
    expect(userInstall!.installDir).toBe(claudeDir);
    expect(userInstall!.configFiles).toHaveLength(1);
  });

  it('loads both settings.json and settings.local.json', async () => {
    const settingsPath = join(claudeDir, 'settings.json');
    const localPath = join(claudeDir, 'settings.local.json');
    setExistingPaths([claudeDir, settingsPath, localPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === settingsPath) return mockConfig(settingsPath, { model: 'opus' });
      if (path === localPath) return mockConfig(localPath, { permissions: { allow: ['Read'] } });
      throw new Error('ENOENT');
    });

    const result = await claudeCodeAdapter.detect();
    const userInstall = result.find(r => !r.profile);
    expect(userInstall!.configFiles).toHaveLength(2);
  });

  it('also picks up ~/.claude.json (root-level state file)', async () => {
    const rootStatePath = join(home, '.claude.json');
    setExistingPaths([rootStatePath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === rootStatePath) return mockConfig(rootStatePath, { projects: {} });
      throw new Error('ENOENT');
    });

    const result = await claudeCodeAdapter.detect();
    const userInstall = result.find(r => !r.profile);
    expect(userInstall).toBeDefined();
    expect(userInstall!.configFiles.some(c => c.filePath === rootStatePath)).toBe(true);
  });

  it('extracts version from CLI', async () => {
    const settingsPath = join(claudeDir, 'settings.json');
    setExistingPaths([claudeDir, settingsPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === settingsPath) return mockConfig(settingsPath, {});
      throw new Error('ENOENT');
    });
    mockExecFileSync.mockReturnValue('1.4.2 (Claude Code)\n' as any);

    const result = await claudeCodeAdapter.detect();
    const userInstall = result.find(r => !r.profile);
    expect(userInstall!.version).toBe('1.4.2');
  });

  it('returns config paths under ~/.claude', () => {
    const paths = claudeCodeAdapter.getConfigPaths();
    expect(paths).toContain(join(claudeDir, 'settings.json'));
    expect(paths).toContain(join(claudeDir, 'settings.local.json'));
    expect(paths).toContain(join(home, '.claude.json'));
  });

  it('returns skills dir relative to install dir', () => {
    expect(claudeCodeAdapter.getSkillsDir(claudeDir)).toBe(join(claudeDir, 'skills'));
  });

  it('has no gateway', () => {
    expect(claudeCodeAdapter.getGatewayInfo({})).toBeUndefined();
  });

  it('returns CLI command', () => {
    expect(claudeCodeAdapter.getCLICommand!()).toBe('claude');
  });

  it('returns probe manifest with expected paths', () => {
    const manifest = claudeCodeAdapter.getProbeManifest!();
    expect(manifest.filePaths).toContain('~/.claude/settings.json');
    expect(manifest.filePaths).toContain('~/.claude/mcp.json');
    expect(manifest.filePaths).toContain('~/.claude.json');
    expect(manifest.envPrefixes).toContain('ANTHROPIC_');
    expect(manifest.envPrefixes).toContain('CLAUDE_');
  });
});
