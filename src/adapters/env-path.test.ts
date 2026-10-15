import { describe, it, expect } from 'vitest';
import { resolve } from 'node:path';
import { envPath, xdgPath } from './env-path.js';
import { codexHome } from './codex.js';
import type { FSProvider } from '../core/fs-provider.js';

describe('relocation variables resolve to absolute paths', () => {
  it('expands ~, keeps absolute paths, resolves relative ones', () => {
    expect(envPath('~', '/home/u')).toBe('/home/u');
    expect(envPath('~/x', '/home/u')).toBe('/home/u/x');
    expect(envPath('/opt/x', '/home/u')).toBe('/opt/x');
    expect(envPath('.codex', '/home/u')).toBe(resolve('.codex'));
    expect(envPath('  ', '/home/u')).toBeUndefined();
  });

  it('ignores a relative XDG base directory (XDG spec)', () => {
    expect(xdgPath('.local/share')).toBeUndefined();
    expect(xdgPath('/x/share')).toBe('/x/share');
  });

  it('CODEX_HOME=.codex gives an absolute Codex home', () => {
    const fs = { homedir: () => '/home/u', getEnv: (k: string) => (k === 'CODEX_HOME' ? '.codex' : undefined) } as unknown as FSProvider;
    expect(codexHome('/home/u', fs)).toBe(resolve('.codex'));
  });
});
