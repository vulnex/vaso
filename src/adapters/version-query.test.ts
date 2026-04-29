import { describe, it, expect, vi } from 'vitest';
import type { FSProvider, DirentInfo } from '../core/fs-provider.js';
import { queryCliVersion, readPackageVersion } from './version-query.js';

function fsWithExec(impl: (binary: string, args: string[]) => string): FSProvider {
  return {
    access: vi.fn(),
    stat: vi.fn(),
    readFile: vi.fn(),
    readdir: vi.fn(),
    readdirEntries: vi.fn(),
    realpath: vi.fn(),
    exec: vi.fn(),
    execSync: vi.fn((binary: string, args?: string[]) => impl(binary, args ?? [])),
    homedir: () => '/home/test',
    platform: 'linux',
  } as unknown as FSProvider;
}

describe('queryCliVersion', () => {
  it('returns undefined when binary is undefined', () => {
    const fs = fsWithExec(() => '1.2.3');
    expect(queryCliVersion(undefined, fs)).toBeUndefined();
  });

  it('extracts a basic semver from --version output', () => {
    const fs = fsWithExec(() => 'mycli 1.2.3\n');
    expect(queryCliVersion('mycli', fs)).toBe('1.2.3');
  });

  it('extracts a semver with a hyphenated pre-release', () => {
    const fs = fsWithExec(() => 'mycli 0.21.0-canary.4');
    expect(queryCliVersion('mycli', fs)).toBe('0.21.0-canary.4');
  });

  it('extracts a semver with a dotted suffix', () => {
    const fs = fsWithExec(() => 'mycli version 1.2.3.4');
    expect(queryCliVersion('mycli', fs)).toBe('1.2.3.4');
  });

  it('returns undefined when output has no semver', () => {
    const fs = fsWithExec(() => 'no version info here');
    expect(queryCliVersion('mycli', fs)).toBeUndefined();
  });

  it('returns undefined when execSync throws', () => {
    const fs = fsWithExec(() => { throw new Error('not found'); });
    expect(queryCliVersion('mycli', fs)).toBeUndefined();
  });

  it('falls through arg sets in order until one yields a semver', () => {
    const calls: string[][] = [];
    const fs = fsWithExec((_, args) => {
      calls.push(args);
      // Only respond to the second arg set
      if (args[0] === '--version') return 'mycli 2.0.0';
      throw new Error('unsupported');
    });
    const result = queryCliVersion('mycli', fs, { argSets: [['version'], ['--version']] });
    expect(result).toBe('2.0.0');
    expect(calls).toEqual([['version'], ['--version']]);
  });

  it('respects the timeout option', () => {
    let recordedTimeout: number | undefined;
    const fs = {
      ...fsWithExec(() => '1.0.0'),
      execSync: vi.fn((_b: string, _a?: string[], opts?: { timeout?: number }) => {
        recordedTimeout = opts?.timeout;
        return '1.0.0';
      }),
    } as unknown as FSProvider;
    queryCliVersion('mycli', fs, { timeoutMs: 500 });
    expect(recordedTimeout).toBe(500);
  });
});

function mkPkgFs(opts: {
  files?: Record<string, string>;
  dirs?: Record<string, DirentInfo[]>;
  realpath?: Record<string, string>;
}): FSProvider {
  const files = opts.files ?? {};
  const dirs = opts.dirs ?? {};
  const realpathMap = opts.realpath ?? {};
  return {
    async readFile(p: string): Promise<string> {
      if (p in files) return files[p];
      throw new Error('ENOENT');
    },
    async access(p: string): Promise<boolean> {
      return p in files || p in dirs;
    },
    async readdirEntries(p: string): Promise<DirentInfo[]> {
      if (p in dirs) return dirs[p];
      throw new Error('ENOENT');
    },
    async realpath(p: string): Promise<string> {
      return realpathMap[p] ?? p;
    },
    readdir: async () => [],
    stat: async () => ({ mode: 0, isFile: () => true, isDirectory: () => false }),
    exec: async () => ({ stdout: '', stderr: '', exitCode: 0 }),
    execSync: () => '',
    getEnv: () => undefined,
    platform: 'linux' as NodeJS.Platform,
    homedir: () => '/home/test',
  };
}

describe('readPackageVersion', () => {
  it('returns undefined for an undefined binary', async () => {
    const fs = mkPkgFs({});
    expect(await readPackageVersion(undefined, fs)).toBeUndefined();
  });

  it('walks up from a resolved symlink to find package.json', async () => {
    const fs = mkPkgFs({
      realpath: {
        '/usr/local/bin/mycli': '/usr/local/lib/node_modules/mycli/dist/index.js',
      },
      files: {
        '/usr/local/lib/node_modules/mycli/package.json': JSON.stringify({
          name: 'mycli',
          version: '3.4.5',
          bin: { mycli: 'dist/index.js' },
        }),
      },
    });
    const result = await readPackageVersion('/usr/local/bin/mycli', fs);
    expect(result).toBe('3.4.5');
  });

  it('finds nvm-installed npm-global package by walking lib/node_modules (object bin)', async () => {
    const binary = '/home/test/.nvm/versions/node/v22.22.1/bin/gemini';
    const nodeModules = '/home/test/.nvm/versions/node/v22.22.1/lib/node_modules';
    const fs = mkPkgFs({
      // realpath returns the binary unchanged (snapshot mode without symlink data)
      dirs: {
        [nodeModules]: [
          { name: '@google', isFile: false, isDirectory: true },
          { name: 'npm', isFile: false, isDirectory: true },
        ],
        [`${nodeModules}/@google`]: [
          { name: 'gemini-cli', isFile: false, isDirectory: true },
        ],
      },
      files: {
        [`${nodeModules}/@google/gemini-cli/package.json`]: JSON.stringify({
          name: '@google/gemini-cli',
          version: '0.13.4',
          bin: { gemini: 'dist/index.js' },
        }),
        [`${nodeModules}/npm/package.json`]: JSON.stringify({
          name: 'npm',
          version: '10.0.0',
          bin: { npm: 'bin/npm-cli.js' },
        }),
      },
    });
    const result = await readPackageVersion(binary, fs);
    expect(result).toBe('0.13.4');
  });

  it('matches a string-form bin against the package name tail', async () => {
    const binary = '/home/test/.nvm/versions/node/v22.22.1/bin/qwen';
    const nodeModules = '/home/test/.nvm/versions/node/v22.22.1/lib/node_modules';
    const fs = mkPkgFs({
      dirs: {
        [nodeModules]: [
          { name: '@qwen-code', isFile: false, isDirectory: true },
        ],
        [`${nodeModules}/@qwen-code`]: [
          { name: 'qwen-code', isFile: false, isDirectory: true },
        ],
      },
      files: {
        [`${nodeModules}/@qwen-code/qwen-code/package.json`]: JSON.stringify({
          name: '@qwen-code/qwen-code',
          version: '1.2.3',
          bin: 'dist/index.js',
        }),
      },
    });
    const result = await readPackageVersion(binary, fs);
    // Single-string bin uses package name tail; "@qwen-code/qwen-code" → "qwen-code", not "qwen"
    expect(result).toBeUndefined();
  });

  it('returns undefined when binary is not in a `bin/` directory', async () => {
    const fs = mkPkgFs({});
    const result = await readPackageVersion('/opt/weird/path/myagent', fs);
    expect(result).toBeUndefined();
  });

  it('returns undefined when lib/node_modules does not exist', async () => {
    const fs = mkPkgFs({});
    const result = await readPackageVersion('/usr/local/bin/missing', fs);
    expect(result).toBeUndefined();
  });

  it('direct npm-global lookup works without dir listings (snapshot mode)', async () => {
    const binary = '/home/test/.nvm/versions/node/v22.22.1/bin/gemini';
    const pkgPath = '/home/test/.nvm/versions/node/v22.22.1/lib/node_modules/@google/gemini-cli/package.json';
    // Note: no `dirs` mapping — simulating snapshot FS that didn't capture
    // the node_modules directory listing. Only the package.json file is
    // present (captured via probe glob).
    const fs = mkPkgFs({
      files: {
        [pkgPath]: JSON.stringify({ name: '@google/gemini-cli', version: '0.42.0', bin: { gemini: 'dist/index.js' } }),
      },
    });
    const result = await readPackageVersion(binary, fs, '@google/gemini-cli');
    expect(result).toBe('0.42.0');
  });

  it('direct lookup tries the exact package path (handles scoped names)', async () => {
    const binary = '/home/test/.nvm/versions/node/v22.22.1/bin/qwen';
    const pkgPath = '/home/test/.nvm/versions/node/v22.22.1/lib/node_modules/@qwen-code/qwen-code/package.json';
    const fs = mkPkgFs({
      files: {
        [pkgPath]: JSON.stringify({ name: '@qwen-code/qwen-code', version: '0.15.3', bin: 'dist/index.js' }),
      },
    });
    const result = await readPackageVersion(binary, fs, '@qwen-code/qwen-code');
    expect(result).toBe('0.15.3');
  });

  it('direct lookup returns undefined when package name does not match the snapshot', async () => {
    const binary = '/home/test/.nvm/versions/node/v22.22.1/bin/gemini';
    const fs = mkPkgFs({}); // no files at all
    const result = await readPackageVersion(binary, fs, '@google/gemini-cli');
    expect(result).toBeUndefined();
  });
});
