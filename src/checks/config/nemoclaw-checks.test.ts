import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { ScanContext, AgentInstallation } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';

vi.mock('node:os', () => ({ homedir: () => '/mock-home' }));
vi.mock('node:fs/promises', () => ({
  access: vi.fn(),
  readFile: vi.fn(),
  readdir: vi.fn(),
  realpath: vi.fn(),
}));

import { access, readFile, readdir } from 'node:fs/promises';
import { cfg016 } from './cfg-016-nemoclaw-hardening.js';
import { cfg017 } from './cfg-017-nemoclaw-sandbox-active.js';
import { cfg018 } from './cfg-018-nemoclaw-network-policy.js';
import { cfg019 } from './cfg-019-nemoclaw-blueprint-integrity.js';

const mockAccess = vi.mocked(access);
const mockReadFile = vi.mocked(readFile);
const mockReaddir = vi.mocked(readdir);

function makeContext(): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: '/tmp/test-openclaw',
    configFiles: [],
  };
  return { installation, configs: [], platform: 'linux', fs: new LocalFSProvider() };
}

function allowPath(...paths: string[]) {
  mockAccess.mockImplementation(async (p) => {
    if (paths.some(allowed => (p as string).startsWith(allowed))) return;
    throw new Error('ENOENT');
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockAccess.mockRejectedValue(new Error('ENOENT'));
  mockReadFile.mockRejectedValue(new Error('ENOENT'));
  mockReaddir.mockRejectedValue(new Error('ENOENT'));
});

// --- CFG-016: NemoClaw Hardening ---

describe('CFG-016: NemoClaw Hardening', () => {
  it('fails when ~/.nemoclaw does not exist', async () => {
    const result = await cfg016.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.id).toBe('CFG-016');
    expect(result.message).toContain('not installed');
  });

  it('passes when ~/.nemoclaw exists', async () => {
    allowPath('/mock-home/.nemoclaw');
    const result = await cfg016.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.message).toContain('installed');
    expect(result.evidence).toBeDefined();
    expect(result.evidence!.length).toBeGreaterThanOrEqual(1);
  });

  it('includes state info when state file readable', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockImplementation(async (p) => {
      if ((p as string).includes('nemoclaw.json')) {
        return JSON.stringify({ lastAction: 'launch', blueprintVersion: '0.1.0' });
      }
      throw new Error('ENOENT');
    });
    const result = await cfg016.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.evidence!.some(e => e.detail!.includes('launch'))).toBe(true);
  });

  it('includes config info when config file readable', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockImplementation(async (p) => {
      if ((p as string).includes('config.json')) {
        return JSON.stringify({ endpointType: 'build' });
      }
      throw new Error('ENOENT');
    });
    const result = await cfg016.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.evidence!.some(e => e.detail!.includes('build'))).toBe(true);
  });

  it('has correct metadata', () => {
    expect(cfg016.category).toBe('config');
    expect(cfg016.severity).toBe('info');
    expect(cfg016.supportedAgents).toEqual(['openclaw', 'nemoclaw']);
  });
});

// --- CFG-017: NemoClaw Sandbox Active ---

describe('CFG-017: NemoClaw Sandbox Active', () => {
  it('fails when state file does not exist', async () => {
    const result = await cfg017.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.message).toContain('not found');
  });

  it('fails when state file has no action or runId', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({}));
    const result = await cfg017.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.message).toContain('no sandbox has been deployed');
  });

  it('passes when sandbox is deployed', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({
      lastAction: 'migrate',
      sandboxName: 'my-agent',
      lastRunId: 'run-123',
    }));
    const result = await cfg017.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.message).toContain('my-agent');
    expect(result.message).toContain('migrate');
  });

  it('handles corrupt state file', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue('not valid json{{{');
    const result = await cfg017.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.message).toContain('could not be parsed');
  });

  it('has correct metadata', () => {
    expect(cfg017.severity).toBe('warning');
    expect(cfg017.supportedAgents).toEqual(['openclaw', 'nemoclaw']);
  });
});

// --- CFG-018: NemoClaw Network Policy ---

describe('CFG-018: NemoClaw Network Policy', () => {
  it('fails when NemoClaw not deployed', async () => {
    const result = await cfg018.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.message).toContain('not deployed');
  });

  it('passes when deployed even without local blueprint', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockResolvedValue(JSON.stringify({ blueprintVersion: '0.1.0' }));
    const result = await cfg018.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.message).toContain('configured');
  });

  it('reports policy details when blueprint found', async () => {
    allowPath('/mock-home/.nemoclaw', '/usr/local/lib');
    mockReadFile.mockImplementation(async (p) => {
      const path = p as string;
      if (path.includes('nemoclaw.json')) {
        return JSON.stringify({ blueprintVersion: '0.1.0' });
      }
      if (path.includes('openclaw-sandbox.yaml')) {
        return 'network:\n  default: deny\n  rules:\n    - allow: api.anthropic.com\n    - allow: github.com\n';
      }
      throw new Error('ENOENT');
    });
    mockReaddir.mockImplementation(async (p) => {
      if ((p as string).includes('presets')) {
        return ['discord.yaml', 'slack.yaml'] as unknown as Awaited<ReturnType<typeof readdir>>;
      }
      throw new Error('ENOENT');
    });
    const result = await cfg018.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.message).toContain('configured');
  });

  it('has correct metadata', () => {
    expect(cfg018.severity).toBe('warning');
    expect(cfg018.supportedAgents).toEqual(['openclaw', 'nemoclaw']);
  });
});

// --- CFG-019: NemoClaw Blueprint Integrity ---

describe('CFG-019: NemoClaw Blueprint Integrity', () => {
  it('fails when NemoClaw not installed', async () => {
    const result = await cfg019.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.message).toContain('not installed');
  });

  it('fails when installed but no artifacts found', async () => {
    allowPath('/mock-home/.nemoclaw');
    const result = await cfg019.run(makeContext());
    expect(result.passed).toBe(false);
    expect(result.message).toContain('no blueprint artifacts');
  });

  it('passes when cached blueprint exists', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReaddir.mockImplementation(async (p) => {
      if ((p as string).includes('blueprints')) {
        return ['0.1.0'] as unknown as Awaited<ReturnType<typeof readdir>>;
      }
      throw new Error('ENOENT');
    });
    const result = await cfg019.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.evidence).toBeDefined();
  });

  it('notes when using latest tag', async () => {
    allowPath('/mock-home/.nemoclaw', '/usr/local/lib');
    mockReadFile.mockImplementation(async (p) => {
      if ((p as string).includes('openclaw.plugin.json')) {
        return JSON.stringify({ blueprintVersion: 'latest' });
      }
      throw new Error('ENOENT');
    });
    const result = await cfg019.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.message).toContain('latest');
  });

  it('reports rollback capability from state', async () => {
    allowPath('/mock-home/.nemoclaw');
    mockReadFile.mockImplementation(async (p) => {
      if ((p as string).includes('nemoclaw.json')) {
        return JSON.stringify({ migrationSnapshot: '/mock-home/.nemoclaw/snapshots/2026-01-01' });
      }
      throw new Error('ENOENT');
    });
    const result = await cfg019.run(makeContext());
    expect(result.passed).toBe(true);
    expect(result.evidence!.some(e => e.detail!.includes('rollback'))).toBe(true);
  });

  it('has correct metadata', () => {
    expect(cfg019.severity).toBe('info');
    expect(cfg019.supportedAgents).toEqual(['openclaw', 'nemoclaw']);
  });
});
