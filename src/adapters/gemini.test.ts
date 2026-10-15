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
    expect(manifest.metadataGlobPatterns).toContain('~/.gemini/oauth_creds.json');
    expect(manifest.filePaths).not.toContain('~/.gemini/oauth_creds.json');
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

describe('geminiHome', () => {
  const fsWith = (env: Record<string, string>, home = '/home/u') => ({ homedir: () => home, getEnv: (k: string) => env[k] }) as unknown as import('../core/fs-provider.js').FSProvider;
  it('puts .gemini under $GEMINI_CLI_HOME for the scanning user', async () => {
    const { geminiHome } = await import('./gemini.js');
    expect(geminiHome('/home/u', fsWith({}))).toBe('/home/u/.gemini');
    expect(geminiHome('/home/u', fsWith({ GEMINI_CLI_HOME: '/srv/job' }))).toBe('/srv/job/.gemini');
    expect(geminiHome('/home/x', fsWith({ GEMINI_CLI_HOME: '/srv/job' }))).toBe('/home/x/.gemini');
  });
});

describe('Gemini CLI adapter — system settings', () => {
  const HOME = '/home/tester';
  function fakeFs(files: Record<string, string>, env: Record<string, string> = {}, platform = 'linux'): import('../core/fs-provider.js').FSProvider {
    const paths = new Set<string>();
    for (const key of Object.keys(files)) {
      let p = key;
      paths.add(p);
      while ((p = p.slice(0, p.lastIndexOf('/'))) && p.length > 0) paths.add(p);
    }
    return {
      platform,
      homedir: () => HOME,
      getEnv: (k: string) => env[k],
      access: async (p: string) => paths.has(p),
      readFile: async (p: string) => {
        if (!(p in files)) throw new Error(`ENOENT ${p}`);
        return files[p];
      },
      readdirEntries: async () => { throw new Error('ENOENT'); },
      execSync: () => { throw new Error('not found'); },
    } as unknown as import('../core/fs-provider.js').FSProvider;
  }

  it('loads /etc/gemini-cli/settings.json (Linux) into the user install', async () => {
    const fs = fakeFs({
      [`${HOME}/.gemini/settings.json`]: '{}',
      '/etc/gemini-cli/settings.json': '{ "tools": { "approvalMode": "auto_edit" } }',
    });
    const [inst] = await geminiAdapter.detect({ fs });
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${HOME}/.gemini/settings.json`, '/etc/gemini-cli/settings.json']);
  });

  it('honours GEMINI_CLI_SYSTEM_SETTINGS_PATH and the macOS location', async () => {
    const custom = fakeFs({ [`${HOME}/.gemini/settings.json`]: '{}', '/opt/policy/gemini.json': '{}' },
      { GEMINI_CLI_SYSTEM_SETTINGS_PATH: '/opt/policy/gemini.json' });
    expect((await geminiAdapter.detect({ fs: custom }))[0].configFiles.map(c => c.filePath)).toContain('/opt/policy/gemini.json');
    const mac = fakeFs({ [`${HOME}/.gemini/settings.json`]: '{}', '/Library/Application Support/GeminiCli/settings.json': '{}' }, {}, 'darwin');
    expect((await geminiAdapter.detect({ fs: mac }))[0].configFiles.map(c => c.filePath))
      .toContain('/Library/Application Support/GeminiCli/settings.json');
  });

  it('does not create an install from system settings alone', async () => {
    const fs = fakeFs({ '/etc/gemini-cli/settings.json': '{}' });
    expect(await geminiAdapter.detect({ fs })).toEqual([]);
  });
});
