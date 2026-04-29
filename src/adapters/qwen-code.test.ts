import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { qwenCodeAdapter } from './qwen-code.js';

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

import { access, readFile } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';

const mockAccess = vi.mocked(access);
const mockReadFile = vi.mocked(readFile);
const mockExecFileSync = vi.mocked(execFileSync);

function setExistingPaths(paths: string[]): void {
  const set = new Set(paths);
  mockAccess.mockImplementation(async (path) => {
    if (set.has(path as string)) return undefined;
    throw new Error('ENOENT');
  });
}

describe('Qwen Code adapter', () => {
  const home = process.env.HOME || '/home/testuser';
  const qwenDir = join(home, '.qwen');

  beforeEach(() => {
    vi.resetAllMocks();
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
  });

  it('returns empty array when nothing is present', async () => {
    setExistingPaths([]);
    const result = await qwenCodeAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from settings.json with model.name + selected provider', async () => {
    const settingsPath = join(qwenDir, 'settings.json');
    setExistingPaths([qwenDir, settingsPath]);
    mockReadFile.mockImplementation(async () => JSON.stringify({
      model: { name: 'qwen-coder-plus' },
      security: { auth: { selectedType: 'openai' } },
    }));

    const result = await qwenCodeAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('qwen-code');
    expect(result[0].models).toEqual([{ id: 'qwen-coder-plus', provider: 'openai' }]);
  });

  it('falls back to modelProviders when no model.name', async () => {
    const settingsPath = join(qwenDir, 'settings.json');
    setExistingPaths([qwenDir, settingsPath]);
    mockReadFile.mockImplementation(async () => JSON.stringify({
      modelProviders: [{ id: 'qwen3-coder-480b', envKey: 'DASHSCOPE_API_KEY' }],
      security: { auth: { selectedType: 'qwen' } },
    }));

    const result = await qwenCodeAdapter.detect();
    expect(result[0].models).toEqual([{ id: 'qwen3-coder-480b', provider: 'qwen' }]);
  });

  it('reports installation when CLI binary exists but no config dir', async () => {
    setExistingPaths(['/usr/local/bin/qwen']);
    const result = await qwenCodeAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe('/usr/local/bin/qwen');
  });

  it('returns config paths under ~/.qwen', () => {
    const paths = qwenCodeAdapter.getConfigPaths();
    expect(paths).toContain(join(qwenDir, 'settings.json'));
  });

  it('returns CLI command', () => {
    expect(qwenCodeAdapter.getCLICommand!()).toBe('qwen');
  });

  it('probe manifest includes Dashscope and Bailian env prefixes', () => {
    const manifest = qwenCodeAdapter.getProbeManifest!();
    expect(manifest.filePaths).toContain('~/.qwen/settings.json');
    expect(manifest.envPrefixes).toContain('QWEN_');
    expect(manifest.envPrefixes).toContain('DASHSCOPE_');
    expect(manifest.envPrefixes).toContain('BAILIAN_');
  });

  it('credential paths include MCP OAuth tokens', () => {
    const paths = qwenCodeAdapter.getCredentialPaths!(qwenDir);
    expect(paths).toContain(join(qwenDir, 'mcp-oauth-tokens.json'));
  });
});
