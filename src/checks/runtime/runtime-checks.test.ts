import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { run001 } from './run-001-launch-agents.js';
import { run005 } from './run-005-process-ancestry.js';

function makeContext(): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: '/tmp/test-openclaw',
    configFiles: [],
  };
  return { installation, configs: [], platform: process.platform as NodeJS.Platform, fs: new LocalFSProvider() };
}

function makeMockedFs(filesByDir: Record<string, string[]>, platform: NodeJS.Platform = 'darwin'): FSProvider {
  return {
    readdir: vi.fn(async (dir: string) => filesByDir[dir] ?? []),
    readFile: vi.fn(async () => ''),
    readdirEntries: vi.fn(async () => []),
    access: vi.fn(async () => true),
    stat: vi.fn(),
    realpath: vi.fn(),
    exec: vi.fn(),
    execSync: vi.fn(),
    homedir: () => '/home/test',
    platform,
  } as FSProvider;
}

function makeRunCtx(fs: FSProvider, platform: NodeJS.Platform = 'darwin'): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: '/home/test/.openclaw',
    configFiles: [],
  };
  return { installation, configs: [], platform, fs };
}

describe('RUN-001: Unauthorized LaunchAgents', () => {
  it('does not flag generic Apple/Google/Microsoft LaunchAgents with "agent" in the name', async () => {
    const fs = makeMockedFs({
      '/home/test/Library/LaunchAgents': [
        'com.google.keystone.agent.plist',
        'com.microsoft.update.agent.plist',
        'com.apple.SafariBookmarksSyncAgent.plist',
      ],
      '/Library/LaunchAgents': [],
      '/Library/LaunchDaemons': [],
    });
    const result = await run001.run(makeRunCtx(fs));
    expect(result.passed).toBe(true);
  });

  it('flags LaunchAgents that reference *claw frameworks', async () => {
    const fs = makeMockedFs({
      '/home/test/Library/LaunchAgents': ['com.openclaw.gateway.plist'],
      '/Library/LaunchAgents': [],
      '/Library/LaunchDaemons': [],
    });
    const result = await run001.run(makeRunCtx(fs));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].file).toContain('openclaw');
  });

  it('flags LaunchAgents that reference nanobot', async () => {
    const fs = makeMockedFs({
      '/home/test/Library/LaunchAgents': ['com.nanobot.persistence.plist'],
      '/Library/LaunchAgents': [],
      '/Library/LaunchDaemons': [],
    });
    const result = await run001.run(makeRunCtx(fs));
    expect(result.passed).toBe(false);
  });

  it('does not match the generic word "skill"', async () => {
    const fs = makeMockedFs({
      '/home/test/Library/LaunchAgents': ['com.amazon.alexa.skill-builder.plist'],
      '/Library/LaunchAgents': [],
      '/Library/LaunchDaemons': [],
    });
    const result = await run001.run(makeRunCtx(fs));
    expect(result.passed).toBe(true);
  });

  it('passes when no LaunchAgents directories are readable', async () => {
    const fs: FSProvider = {
      readdir: vi.fn(async () => { throw new Error('ENOENT'); }),
      readFile: vi.fn(async () => ''),
      readdirEntries: vi.fn(async () => []),
      access: vi.fn(async () => false),
      stat: vi.fn(),
      realpath: vi.fn(),
      exec: vi.fn(),
      execSync: vi.fn(),
      homedir: () => '/home/test',
      platform: 'darwin',
    } as FSProvider;
    const result = await run001.run(makeRunCtx(fs));
    expect(result.passed).toBe(true);
  });
});

describe('RUN-005: Process Ancestry Analysis', () => {
  it('returns a valid CheckResult', async () => {
    const result = await run005.run(makeContext());
    expect(result.id).toBe('RUN-005');
    expect(result.category).toBe('runtime');
    expect(result.severity).toBe('warning');
    expect(typeof result.passed).toBe('boolean');
    expect(typeof result.message).toBe('string');
  });

  it('is limited to darwin and linux platforms', () => {
    expect(run005.supportedPlatforms).toEqual(['darwin', 'linux']);
  });

  it('passes when no agent processes are running', async () => {
    // In a test environment, no openclaw/nanoclaw/etc processes should be running
    const result = await run005.run(makeContext());
    expect(result.passed).toBe(true);
  });
});
