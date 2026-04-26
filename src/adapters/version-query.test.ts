import { describe, it, expect, vi } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import { queryCliVersion } from './version-query.js';

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
