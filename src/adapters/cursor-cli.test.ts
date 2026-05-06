import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { cursorCliAdapter } from './cursor-cli.js';

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
  return { raw: '', format: 'json' as const, filePath, data };
}

describe('Cursor CLI adapter', () => {
  const home = process.env.HOME || '/home/testuser';
  const cursorDir = join(home, '.cursor');

  beforeEach(() => {
    vi.resetAllMocks();
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
  });

  it('returns empty array when nothing is present', async () => {
    setExistingPaths([]);
    const result = await cursorCliAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from cli-config.json', async () => {
    const configPath = join(cursorDir, 'cli-config.json');
    setExistingPaths([cursorDir, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, { version: 1, permissions: { allow: ['Shell(git)'] } });
      }
      throw new Error('ENOENT');
    });

    const result = await cursorCliAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('cursor-cli');
    expect(result[0].installDir).toBe(cursorDir);
    expect(result[0].configFiles).toHaveLength(1);
  });

  it('returns no models when config has no model field', async () => {
    const configPath = join(cursorDir, 'cli-config.json');
    setExistingPaths([cursorDir, configPath]);
    mockLoadConfig.mockResolvedValue(mockConfig(configPath, {}));
    const result = await cursorCliAdapter.detect();
    expect(result[0].models).toEqual([]);
  });

  it('extracts the active model from selectedModel.modelId', async () => {
    const configPath = join(cursorDir, 'cli-config.json');
    setExistingPaths([cursorDir, configPath]);
    mockLoadConfig.mockResolvedValue(mockConfig(configPath, {
      model: { modelId: 'composer-1' },
      selectedModel: { modelId: 'composer-2' },
    }));
    const result = await cursorCliAdapter.detect();
    expect(result[0].models).toEqual([{ id: 'composer-2', provider: 'cursor' }]);
  });

  it('falls back to model.modelId when selectedModel is absent', async () => {
    const configPath = join(cursorDir, 'cli-config.json');
    setExistingPaths([cursorDir, configPath]);
    mockLoadConfig.mockResolvedValue(mockConfig(configPath, {
      model: { modelId: 'composer-1' },
    }));
    const result = await cursorCliAdapter.detect();
    expect(result[0].models).toEqual([{ id: 'composer-1', provider: 'cursor' }]);
  });

  it('reports installation when CLI binary exists at cursor-agent path', async () => {
    setExistingPaths(['/usr/local/bin/cursor-agent']);
    const result = await cursorCliAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe('/usr/local/bin/cursor-agent');
  });

  it('does not detect ~/.cursor/ from the Cursor IDE without CLI signals', async () => {
    // ~/.cursor/ is shared with the Cursor IDE (argv.json, extensions/,
    // projects/, ide_state.json). Without `cli-config.json` / `mcp.json` or
    // a `cursor-agent` binary, this is the IDE, not the CLI.
    setExistingPaths([cursorDir]);
    const result = await cursorCliAdapter.detect();
    expect(result).toEqual([]);
  });

  it('returns config paths under ~/.cursor', () => {
    const paths = cursorCliAdapter.getConfigPaths();
    expect(paths).toContain(join(cursorDir, 'cli-config.json'));
    expect(paths).toContain(join(cursorDir, 'mcp.json'));
  });

  it('returns CLI command', () => {
    expect(cursorCliAdapter.getCLICommand!()).toBe('cursor-agent');
  });

  it('probe manifest includes both cursor-agent and agent binary paths', () => {
    const manifest = cursorCliAdapter.getProbeManifest!();
    expect(manifest.filePaths).toContain('~/.cursor/cli-config.json');
    expect(manifest.filePaths).toContain('~/.cursor/mcp.json');
    expect(manifest.filePaths).toContain('~/.local/bin/cursor-agent');
    expect(manifest.filePaths).toContain('~/.local/bin/agent');
    expect(manifest.envPrefixes).toContain('CURSOR_');
  });

  it('credential paths surface cli-config.json + mcp.json', () => {
    const paths = cursorCliAdapter.getCredentialPaths!(cursorDir);
    expect(paths).toContain(join(cursorDir, 'cli-config.json'));
  });
});
