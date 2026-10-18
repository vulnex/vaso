import { describe, it, expect } from 'vitest';
import type { FSProvider } from '../../core/fs-provider.js';
import type { ScanContext } from '../../core/types.js';
import { pol003 } from './pol-003-session-credentials.js';
import { geminiAdapter } from '../../adapters/gemini.js';
import { qwenCodeAdapter } from '../../adapters/qwen-code.js';
import { claudeCodeAdapter } from '../../adapters/claude-code.js';
import { codexAdapter } from '../../adapters/codex.js';

function fsWith(files: Record<string, string>, mode = 0o100644): FSProvider {
  return {
    kind: 'local',
    platform: 'linux',
    homedir: () => '/home/t',
    getEnv: () => undefined,
    access: async (p: string) => p in files,
    stat: async (p: string) => {
      if (!(p in files)) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
      return { mode, isFile: () => true, isDirectory: () => false };
    },
    readFile: async (p: string) => {
      if (!(p in files)) throw new Error('ENOENT');
      return files[p];
    },
    realpath: async (p: string) => p,
  } as unknown as FSProvider;
}

function ctx(credentialPaths: string[], files: Record<string, string>): ScanContext {
  return {
    installation: { agent: 'gemini-cli', installDir: '/home/t/.gemini', configFiles: [] },
    configs: [],
    platform: 'linux',
    fs: fsWith(files),
    credentialPaths,
  };
}

describe('POL-003 and declared paths that did not load', () => {
  const settings = '/home/t/.gemini/settings.json';

  it('an unparseable settings file without a key is not a credential leak', async () => {
    const r = await pol003.run(ctx([settings], { [settings]: '{ "theme": "dark", oops' }));
    expect(r.passed).toBe(true);
  });

  it('an unparseable settings file with a key still is', async () => {
    const r = await pol003.run(ctx([settings], { [settings]: '{ "env": { "K": "AIza-not-matched", "O": "sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1w" }, oops' }));
    expect(r.passed).toBe(false);
  });

  it('a token store counts whatever it holds', async () => {
    const tokens = '/home/t/.gemini/oauth_creds.json';
    const r = await pol003.run(ctx([tokens], { [tokens]: '{}' }));
    expect(r.passed).toBe(false);
  });
});

describe('secret-holding settings files are declared credential paths', () => {
  const fs = fsWith({});
  it('Gemini and Qwen declare settings.json and .env', () => {
    expect(geminiAdapter.getCredentialPaths!('/home/t/.gemini', fs)).toEqual(expect.arrayContaining(['/home/t/.gemini/settings.json', '/home/t/.gemini/.env']));
    expect(qwenCodeAdapter.getCredentialPaths!('/home/t/.qwen', fs)).toEqual(expect.arrayContaining(['/home/t/.qwen/settings.json', '/home/t/.qwen/.env']));
  });
  it('Claude Code declares ~/.claude.json; Codex declares config.toml', () => {
    expect(claudeCodeAdapter.getCredentialPaths!('/home/t/.claude', fs)).toContain('/home/t/.claude.json');
    expect(codexAdapter.getCredentialPaths!('/home/t/.codex', fs)).toContain('/home/t/.codex/config.toml');
  });
});
