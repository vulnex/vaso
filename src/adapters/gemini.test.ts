import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { geminiAdapter } from './gemini.js';

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

describe('Gemini CLI adapter', () => {
  const home = process.env.HOME || '/home/testuser';
  const geminiDir = join(home, '.gemini');

  beforeEach(() => {
    vi.resetAllMocks();
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
  });

  it('returns empty array when nothing is present', async () => {
    setExistingPaths([]);
    const result = await geminiAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from settings.json with model.name', async () => {
    const settingsPath = join(geminiDir, 'settings.json');
    setExistingPaths([geminiDir, settingsPath]);
    mockReadFile.mockImplementation(async (path) => {
      if (path === settingsPath) {
        return JSON.stringify({ model: { name: 'gemini-2.5-pro' } });
      }
      throw new Error('ENOENT');
    });

    const result = await geminiAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('gemini-cli');
    expect(result[0].installDir).toBe(geminiDir);
    expect(result[0].models).toEqual([{ id: 'gemini-2.5-pro', provider: 'google' }]);
  });

  it('parses JSONC settings (comments + trailing commas)', async () => {
    const settingsPath = join(geminiDir, 'settings.json');
    setExistingPaths([geminiDir, settingsPath]);
    mockReadFile.mockImplementation(async () => `{
      // pinned model
      "model": { "name": "gemini-2.5-flash" }, /* block */
      "tools": { "allowed": ["run_shell_command(git)"], },
    }`);

    const result = await geminiAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].models).toEqual([{ id: 'gemini-2.5-flash', provider: 'google' }]);
  });

  it('reports installation when CLI binary exists but no config dir', async () => {
    setExistingPaths(['/usr/local/bin/gemini']);
    const result = await geminiAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe('/usr/local/bin/gemini');
    expect(result[0].configFiles).toHaveLength(0);
  });

  it('does not detect a bare ~/.gemini/ with no recognized configs and no CLI binary', async () => {
    setExistingPaths([geminiDir]);
    const result = await geminiAdapter.detect();
    expect(result).toEqual([]);
  });

  it('returns config paths under ~/.gemini', () => {
    const paths = geminiAdapter.getConfigPaths();
    expect(paths).toContain(join(geminiDir, 'settings.json'));
  });

  it('has no skills dir', () => {
    expect(geminiAdapter.getSkillsDir(geminiDir)).toBeUndefined();
  });

  it('returns CLI command', () => {
    expect(geminiAdapter.getCLICommand!()).toBe('gemini');
  });

  it('returns probe manifest with expected paths and env prefixes', () => {
    const manifest = geminiAdapter.getProbeManifest!();
    expect(manifest.filePaths).toContain('~/.gemini/settings.json');
    expect(manifest.filePaths).toContain('~/.gemini/oauth_creds.json');
    expect(manifest.envPrefixes).toContain('GEMINI_');
    expect(manifest.envPrefixes).toContain('GOOGLE_');
  });

  it('credential paths include OAuth creds files', () => {
    const paths = geminiAdapter.getCredentialPaths!(geminiDir);
    expect(paths).toContain(join(geminiDir, 'oauth_creds.json'));
    expect(paths).toContain(join(geminiDir, 'mcp-oauth-tokens.json'));
  });

  it('memory files include GEMINI.md', () => {
    const files = geminiAdapter.getMemoryFiles!(geminiDir);
    expect(files).toContain(join(geminiDir, 'GEMINI.md'));
  });
});
