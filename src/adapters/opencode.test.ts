import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { opencodeAdapter } from './opencode.js';

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

describe('OpenCode adapter', () => {
  const home = process.env.HOME || '/home/testuser';
  const configDir = join(home, '.config', 'opencode');
  const dataDir = join(home, '.local', 'share', 'opencode');

  beforeEach(() => {
    vi.resetAllMocks();
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
    // Ensure XDG_CONFIG_HOME/XDG_DATA_HOME aren't set in the test environment
    delete process.env.XDG_CONFIG_HOME;
    delete process.env.XDG_DATA_HOME;
  });

  it('returns empty array when nothing is present', async () => {
    setExistingPaths([]);
    const result = await opencodeAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from opencode.json', async () => {
    const configPath = join(configDir, 'opencode.json');
    setExistingPaths([configPath]);
    mockReadFile.mockImplementation(async (path) => {
      if (path === configPath) {
        return JSON.stringify({ model: 'anthropic/claude-opus-4-5', share: 'manual' });
      }
      throw new Error('ENOENT');
    });

    const result = await opencodeAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('opencode');
    expect(result[0].installDir).toBe(configDir);
    expect(result[0].configFiles).toHaveLength(1);
    expect(result[0].models).toEqual([{ provider: 'anthropic', id: 'claude-opus-4-5' }]);
  });

  it('parses JSONC with comments and trailing commas', async () => {
    const configPath = join(configDir, 'opencode.jsonc');
    setExistingPaths([configPath]);
    mockReadFile.mockImplementation(async () => `{
      // line comment
      "model": "openai/gpt-4o", /* block comment */
      "small_model": "anthropic/claude-haiku-4-5",
    }`);

    const result = await opencodeAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].configFiles[0].data).toEqual({
      model: 'openai/gpt-4o',
      small_model: 'anthropic/claude-haiku-4-5',
    });
    expect(result[0].models).toEqual([
      { provider: 'openai', id: 'gpt-4o' },
      { provider: 'anthropic', id: 'claude-haiku-4-5', via: 'small_model' },
    ]);
  });

  it('reports installation when only auth.json exists', async () => {
    setExistingPaths([join(dataDir, 'auth.json')]);
    const result = await opencodeAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].configFiles).toHaveLength(0);
  });

  it('reports installation when CLI binary exists but no config', async () => {
    setExistingPaths(['/usr/local/bin/opencode']);
    const result = await opencodeAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe('/usr/local/bin/opencode');
  });

  it('does not detect a bare ~/.opencode/ with no config, no auth, and no CLI binary', async () => {
    // ~/.opencode/ alone (without bin/opencode, opencode.json[c], or auth.json)
    // is not a valid install signal. findCLIBinary already covers
    // ~/.opencode/bin/opencode, so a stray dir at this path can be ignored.
    setExistingPaths([join(home, '.opencode')]);
    const result = await opencodeAdapter.detect();
    expect(result).toEqual([]);
  });

  it('honors XDG_CONFIG_HOME override', async () => {
    process.env.XDG_CONFIG_HOME = '/tmp/custom-xdg';
    const configPath = '/tmp/custom-xdg/opencode/opencode.json';
    setExistingPaths([configPath]);
    mockReadFile.mockResolvedValue('{}');

    const result = await opencodeAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].installDir).toBe('/tmp/custom-xdg/opencode');
  });

  it('returns config paths under XDG config dir', () => {
    const paths = opencodeAdapter.getConfigPaths();
    expect(paths.some(p => p.endsWith('opencode.json'))).toBe(true);
    expect(paths.some(p => p.endsWith('opencode.jsonc'))).toBe(true);
  });

  it('has no skills dir', () => {
    expect(opencodeAdapter.getSkillsDir(configDir)).toBeUndefined();
  });

  it('has no gateway', () => {
    expect(opencodeAdapter.getGatewayInfo({})).toBeUndefined();
  });

  it('returns CLI command', () => {
    expect(opencodeAdapter.getCLICommand!()).toBe('opencode');
  });

  it('returns probe manifest with XDG paths and OPENCODE_ env prefix', () => {
    const manifest = opencodeAdapter.getProbeManifest!();
    expect(manifest.filePaths).toContain('~/.config/opencode/opencode.json');
    expect(manifest.filePaths).toContain('~/.config/opencode/opencode.jsonc');
    expect(manifest.filePaths).toContain('~/.local/share/opencode/auth.json');
    expect(manifest.envPrefixes).toContain('OPENCODE_');
    expect(manifest.envPrefixes).toContain('XDG_');
  });

  it('credential path resolves to data dir auth.json', () => {
    const paths = opencodeAdapter.getCredentialPaths!(configDir);
    expect(paths).toEqual([join(dataDir, 'auth.json')]);
  });

  it('memory files include AGENTS.md', () => {
    const files = opencodeAdapter.getMemoryFiles!(configDir);
    expect(files).toContain(join(configDir, 'AGENTS.md'));
  });
});
