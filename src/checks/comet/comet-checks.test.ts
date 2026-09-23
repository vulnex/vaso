import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { cometChecks } from './index.js';

function makeFs(overrides: Partial<FSProvider> = {}): FSProvider {
  return {
    access: vi.fn(async () => true),
    stat: vi.fn(async () => ({ mode: 0o600, isFile: () => true, isDirectory: () => false })),
    readFile: vi.fn(),
    readdir: vi.fn(async () => []),
    readdirEntries: vi.fn(),
    realpath: vi.fn(),
    exec: vi.fn(),
    execSync: vi.fn(),
    getEnv: vi.fn(() => undefined),
    homedir: () => '/Users/test',
    platform: 'darwin',
    ...overrides,
  } as FSProvider;
}

function makeCtx(fs?: FSProvider): ScanContext {
  const configs: ParsedConfig[] = [];
  const installation: AgentInstallation = {
    agent: 'comet',
    installDir: '/Users/test/Library/Application Support/Comet',
    configFiles: configs,
  };
  return { installation, configs, platform: 'darwin', fs: fs ?? makeFs() };
}

describe('Comet checks', () => {
  it('exports 2 checks with correct shape', () => {
    expect(cometChecks).toHaveLength(2);
    for (const check of cometChecks) {
      expect(check.category).toBe('coding-agent');
      expect(check.supportedAgents).toContain('comet');
      expect(check.id).toMatch(/^PC-0\d{2}$/);
    }
  });
});

describe('PC-001: Profile Data Readable by Others', () => {
  const check = cometChecks.find(c => c.id === 'PC-001')!;

  it('flags world-readable Cookies file', async () => {
    const fs = makeFs({
      stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx(fs));
    expect(result.passed).toBe(false);
  });

  it('passes when profile files are 0600', async () => {
    const fs = makeFs({
      stat: vi.fn(async () => ({ mode: 0o600, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx(fs));
    expect(result.passed).toBe(true);
  });

  it('passes when profile absent', async () => {
    const fs = makeFs({ access: vi.fn(async () => false) });
    const result = await check.run(makeCtx(fs));
    expect(result.passed).toBe(true);
  });
});

describe('PC-002: Extension Inventory', () => {
  const check = cometChecks.find(c => c.id === 'PC-002')!;

  it('inventories installed extensions with manifest names', async () => {
    const fs = makeFs({
      readdir: vi.fn(async (p: string) => {
        if (p.endsWith('Extensions')) return ['abcdefghij'];
        return ['1.2.3'];
      }),
      readFile: vi.fn(async () => JSON.stringify({ name: 'Some Extension' })),
    });
    const result = await check.run(makeCtx(fs));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('info');
    expect(result.evidence?.[0]?.detail).toContain('Some Extension');
  });

  it('passes with no extensions dir', async () => {
    const fs = makeFs({ access: vi.fn(async () => false) });
    const result = await check.run(makeCtx(fs));
    expect(result.passed).toBe(true);
  });
});
