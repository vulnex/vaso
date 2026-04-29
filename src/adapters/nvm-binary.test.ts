import { describe, it, expect } from 'vitest';
import { findNvmBinary, nvmBinaryGlob } from './nvm-binary.js';
import type { FSProvider, DirentInfo } from '../core/fs-provider.js';

function mkFs(opts: {
  nvmDirs?: string[];
  existingPaths?: string[];
  throwOnReaddir?: boolean;
}): FSProvider {
  const existing = new Set(opts.existingPaths ?? []);
  return {
    async readdirEntries(_path: string): Promise<DirentInfo[]> {
      if (opts.throwOnReaddir) throw new Error('ENOENT');
      return (opts.nvmDirs ?? []).map(name => ({ name, isFile: false, isDirectory: true }));
    },
    async access(p: string): Promise<boolean> {
      return existing.has(p);
    },
    // Unused — provide minimal stubs to satisfy the type
    readFile: async () => '',
    readdir: async () => [],
    stat: async () => ({ mode: 0, isFile: () => true, isDirectory: () => false }),
    realpath: async (p: string) => p,
    exec: async () => ({ stdout: '', stderr: '', exitCode: 0 }),
    execSync: () => '',
    getEnv: () => undefined,
    platform: 'linux' as NodeJS.Platform,
    homedir: () => '/home/test',
  };
}

describe('findNvmBinary', () => {
  it('returns undefined when ~/.nvm is missing', async () => {
    const fs = mkFs({ throwOnReaddir: true });
    const result = await findNvmBinary('/home/test', fs, 'gemini');
    expect(result).toBeUndefined();
  });

  it('returns undefined when no version dirs match', async () => {
    const fs = mkFs({ nvmDirs: ['v22.22.1'], existingPaths: [] });
    const result = await findNvmBinary('/home/test', fs, 'gemini');
    expect(result).toBeUndefined();
  });

  it('finds binary in the only installed version', async () => {
    const fs = mkFs({
      nvmDirs: ['v22.22.1'],
      existingPaths: ['/home/test/.nvm/versions/node/v22.22.1/bin/gemini'],
    });
    const result = await findNvmBinary('/home/test', fs, 'gemini');
    expect(result).toBe('/home/test/.nvm/versions/node/v22.22.1/bin/gemini');
  });

  it('prefers the newest version when multiple are installed', async () => {
    const fs = mkFs({
      nvmDirs: ['v18.20.0', 'v22.22.1', 'v20.10.0'],
      existingPaths: [
        '/home/test/.nvm/versions/node/v18.20.0/bin/qwen',
        '/home/test/.nvm/versions/node/v22.22.1/bin/qwen',
      ],
    });
    const result = await findNvmBinary('/home/test', fs, 'qwen');
    expect(result).toBe('/home/test/.nvm/versions/node/v22.22.1/bin/qwen');
  });

  it('falls back to older versions if newer is missing the binary', async () => {
    const fs = mkFs({
      nvmDirs: ['v22.22.1', 'v18.20.0'],
      existingPaths: ['/home/test/.nvm/versions/node/v18.20.0/bin/codex'],
    });
    const result = await findNvmBinary('/home/test', fs, 'codex');
    expect(result).toBe('/home/test/.nvm/versions/node/v18.20.0/bin/codex');
  });
});

describe('nvmBinaryGlob', () => {
  it('returns the home-relative glob pattern for a binary', () => {
    expect(nvmBinaryGlob('gemini')).toBe('~/.nvm/versions/node/*/bin/gemini');
    expect(nvmBinaryGlob('cursor-agent')).toBe('~/.nvm/versions/node/*/bin/cursor-agent');
  });
});
