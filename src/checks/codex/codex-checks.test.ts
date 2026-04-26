import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { codexChecks } from './index.js';

function makeConfig(filePath: string, data: Record<string, unknown>): ParsedConfig {
  return {
    raw: '',
    format: 'toml',
    filePath,
    data,
  };
}

function makeFs(overrides: Partial<FSProvider> = {}): FSProvider {
  return {
    access: vi.fn(async () => true),
    stat: vi.fn(async () => ({ mode: 0o600, isFile: () => true, isDirectory: () => false })),
    readFile: vi.fn(),
    readdir: vi.fn(),
    readdirEntries: vi.fn(),
    realpath: vi.fn(),
    exec: vi.fn(),
    execSync: vi.fn(),
    homedir: () => '/home/test',
    platform: 'linux',
    ...overrides,
  } as FSProvider;
}

function makeCtx(configs: ParsedConfig[], fs?: FSProvider): ScanContext {
  const installation: AgentInstallation = {
    agent: 'codex',
    installDir: '/home/test/.codex',
    configFiles: configs,
  };
  return { installation, configs, platform: 'linux', fs: fs ?? makeFs() };
}

describe('Codex checks', () => {
  it('exports 4 checks', () => {
    expect(codexChecks).toHaveLength(4);
  });

  it('all checks have coding-agent category and supportedAgents', () => {
    for (const check of codexChecks) {
      expect(check.category).toBe('coding-agent');
      expect(check.supportedAgents).toContain('codex');
    }
  });

  it('all check IDs start with CDX-', () => {
    for (const check of codexChecks) {
      expect(check.id).toMatch(/^CDX-0\d{2}$/);
    }
  });
});

describe('CDX-001: Codex Approval Policy Disabled', () => {
  const check = codexChecks.find(c => c.id === 'CDX-001')!;

  it('fails when approval_policy = "never"', async () => {
    const result = await check.run(makeCtx([makeConfig('config.toml', { approval_policy: 'never' })]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when approval_policy = "on-request"', async () => {
    const result = await check.run(makeCtx([makeConfig('config.toml', { approval_policy: 'on-request' })]));
    expect(result.passed).toBe(true);
  });
});

describe('CDX-002: Codex Sandbox Disabled', () => {
  const check = codexChecks.find(c => c.id === 'CDX-002')!;

  it('fails when sandbox_mode = "danger-full-access"', async () => {
    const result = await check.run(makeCtx([makeConfig('config.toml', { sandbox_mode: 'danger-full-access' })]));
    expect(result.passed).toBe(false);
  });

  it('passes when sandbox_mode = "workspace-write"', async () => {
    const result = await check.run(makeCtx([makeConfig('config.toml', { sandbox_mode: 'workspace-write' })]));
    expect(result.passed).toBe(true);
  });
});

describe('CDX-003: Codex Auth File Permissions', () => {
  const check = codexChecks.find(c => c.id === 'CDX-003')!;

  it('fails when auth.json is world-readable', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
  });

  it('passes when auth.json is mode 0600', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      stat: vi.fn(async () => ({ mode: 0o600, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });

  it('passes when auth.json is missing', async () => {
    const fs = makeFs({ access: vi.fn(async () => false) });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});

describe('CDX-004: Codex Unpinned MCP Server', () => {
  const check = codexChecks.find(c => c.id === 'CDX-004')!;

  it('fails on npx with no version pin', async () => {
    const config = makeConfig('config.toml', {
      mcp_servers: {
        fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes on npx with pinned version', async () => {
    const config = makeConfig('config.toml', {
      mcp_servers: {
        fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.2.3'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});
