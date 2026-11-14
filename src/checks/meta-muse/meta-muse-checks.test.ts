import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { metaMuseChecks } from './index.js';

function makeConfig(filePath: string, data: Record<string, unknown>): ParsedConfig {
  return { raw: JSON.stringify(data), format: 'json', filePath, data };
}

function makeFs(overrides: Partial<FSProvider> = {}): FSProvider {
  return {
    access: vi.fn(async () => true),
    stat: vi.fn(async () => ({ mode: 0o700, isFile: () => false, isDirectory: () => true })),
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

function makeCtx(configs: ParsedConfig[], fs?: FSProvider, appBundle?: string): ScanContext {
  const installation: AgentInstallation = {
    agent: 'meta-muse',
    installDir: '/Users/test/Library/Application Support/com.meta.endo',
    configFiles: configs,
    appBundle,
  };
  return { installation, configs, platform: 'darwin', fs: fs ?? makeFs() };
}

describe('Meta Muse checks', () => {
  it('exports 3 checks with correct shape', () => {
    expect(metaMuseChecks).toHaveLength(3);
    for (const check of metaMuseChecks) {
      expect(check.category).toBe('coding-agent');
      expect(check.supportedAgents).toContain('meta-muse');
      expect(check.id).toMatch(/^MM-0\d{2}$/);
    }
  });
});

describe('MM-001: Codesign / Team ID', () => {
  const check = metaMuseChecks.find(c => c.id === 'MM-001')!;

  it('passes when app bundle absent', async () => {
    const result = await check.run(makeCtx([]));
    expect(result.passed).toBe(true);
  });

  it('passes on expected Team ID and identifier', async () => {
    const fs = makeFs({
      exec: vi.fn(async () => ({ exitCode: 0, stdout: '', stderr: 'Identifier=com.meta.endo\nTeamIdentifier=V9WTTPBFK9' })),
    });
    const result = await check.run(makeCtx([], fs, '/Applications/Muse.app'));
    expect(result.passed).toBe(true);
  });

  it('fails on unexpected Team ID', async () => {
    const fs = makeFs({
      exec: vi.fn(async () => ({ exitCode: 0, stdout: '', stderr: 'Identifier=com.meta.endo\nTeamIdentifier=ATTACKER99' })),
    });
    const result = await check.run(makeCtx([], fs, '/Applications/Muse.app'));
    expect(result.passed).toBe(false);
  });

  it('fails when unsigned', async () => {
    const fs = makeFs({
      exec: vi.fn(async () => ({ exitCode: 1, stdout: '', stderr: 'code object is not signed at all' })),
    });
    const result = await check.run(makeCtx([], fs, '/Applications/Muse.app'));
    expect(result.passed).toBe(false);
  });

  it('reports not verified (not unsigned) when codesign did not run or ended abnormally', async () => {
    for (const run of [
      { exitCode: 127, stdout: '', stderr: 'Command not collected in snapshot: codesign -dv /Applications/Muse.app' },
      { exitCode: 1, stdout: '', stderr: '' },
    ]) {
      const fs = makeFs({ exec: vi.fn(async () => run) });
      const result = await check.run(makeCtx([], fs, '/Applications/Muse.app'));
      expect(result.passed).toBe(true);
      expect(result.message).toContain('not verified');
    }
  });

  it('does not read TeamIdentifier as the bundle identifier', async () => {
    const fs = makeFs({
      exec: vi.fn(async () => ({ exitCode: 0, stdout: '', stderr: 'TeamIdentifier=V9WTTPBFK9\nIdentifier=com.example.fake' })),
    });
    const result = await check.run(makeCtx([], fs, '/Applications/Muse.app'));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].snippet).toContain('com.example.fake');
  });
});

describe('MM-002: Analytics Telemetry Active', () => {
  const check = metaMuseChecks.find(c => c.id === 'MM-002')!;

  it('flags analytics session keys but not enabled auto-updates (the healthy default)', async () => {
    const result = await check.run(makeCtx([makeConfig('/Users/test/Library/Preferences/com.meta.endo.plist', {
      endo_analytics_session_id: 'F933D4AD',
      endo_analytics_last_event_at: '1790061524',
      SUEnableAutomaticChecks: 1,
      SUAutomaticallyUpdate: true,
    })]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('info');
    expect(result.evidence).toHaveLength(1);
  });

  it('flags disabled Sparkle update checks and automatic installs', async () => {
    const result = await check.run(makeCtx([makeConfig('/Users/test/Library/Preferences/com.meta.endo.plist', {
      SUEnableAutomaticChecks: 0,
      SUAutomaticallyUpdate: false,
    })]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.map(e => e.snippet)).toEqual(['SUEnableAutomaticChecks = 0', 'SUAutomaticallyUpdate = 0']);
  });

  it('passes with no analytics state', async () => {
    const result = await check.run(makeCtx([makeConfig('/Users/test/Library/Preferences/com.meta.endo.plist', {
      endo_dictation_key: 'fn',
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('MM-003: App Data Readable by Others', () => {
  const check = metaMuseChecks.find(c => c.id === 'MM-003')!;

  it('flags group/world-readable data paths', async () => {
    const fs = makeFs({
      readdir: vi.fn(async () => ['analytics']),
      stat: vi.fn(async () => ({ mode: 0o755, isFile: () => false, isDirectory: () => true })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
  });

  it('passes when data dir is 0700', async () => {
    const fs = makeFs({
      readdir: vi.fn(async () => ['analytics']),
      stat: vi.fn(async () => ({ mode: 0o700, isFile: () => false, isDirectory: () => true })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });

  it('passes when dir absent', async () => {
    const fs = makeFs({ access: vi.fn(async () => false) });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});
