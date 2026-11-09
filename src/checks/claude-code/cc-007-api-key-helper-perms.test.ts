import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { cc007 } from './cc-007-api-key-helper-perms.js';

function makeFs(modes: Record<string, number>, overrides: Partial<FSProvider> = {}): FSProvider {
  return {
    access: vi.fn(async (p: string) => p in modes),
    stat: vi.fn(async (p: string) => {
      if (!(p in modes)) throw new Error(`ENOENT: ${p}`);
      return { mode: modes[p], isFile: () => !p.endsWith('/'), isDirectory: () => false };
    }),
    readFile: vi.fn(),
    readdir: vi.fn(),
    readdirEntries: vi.fn(),
    realpath: vi.fn(),
    exec: vi.fn(),
    execSync: vi.fn(),
    getEnv: vi.fn(() => undefined),
    homedir: () => '/home/test',
    platform: 'linux',
    ...overrides,
  } as FSProvider;
}

function ctx(fs: FSProvider): ScanContext {
  const config: ParsedConfig = {
    raw: '', format: 'json', filePath: '/home/test/.claude/settings.json',
    data: { apiKeyHelper: '/home/test/bin/get-key.sh' },
  };
  return {
    installation: { agent: 'claude-code', installDir: '/home/test/.claude', configFiles: [config] },
    configs: [config], platform: 'linux', fs,
  };
}

describe('CC-007 (dt19)', () => {
  it('downgrades a world-writable helper behind a directory others cannot traverse', async () => {
    const result = await cc007.run(ctx(makeFs({
      '/home/test/bin/get-key.sh': 0o100777,
      '/home/test/bin': 0o40755,
      '/home/test': 0o40700,
      '/home': 0o40755,
      '/': 0o40755,
    })));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].mitigated).toBe(true);
    expect(result.severity).toBe('info');
  });

  it('keeps full severity when every ancestor is traversable', async () => {
    const result = await cc007.run(ctx(makeFs({
      '/home/test/bin/get-key.sh': 0o100777,
      '/home/test/bin': 0o40755,
      '/home/test': 0o40755,
      '/home': 0o40755,
      '/': 0o40755,
    })));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].mitigated).toBeFalsy();
    expect(result.severity).toBe('warning');
  });

  it('says a helper the probe did not collect is unverified on snapshots', async () => {
    const fs = makeFs({});
    Object.assign(fs, { kind: 'snapshot' });
    const result = await cc007.run(ctx(fs));
    expect(result.passed).toBe(true);
    expect(result.message).toMatch(/get-key\.sh not verified/);
  });
});
