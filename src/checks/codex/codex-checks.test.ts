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
  it('exports 9 checks', () => {
    expect(codexChecks).toHaveLength(9);
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

describe('CDX-005: Codex Shell Env Inherits All', () => {
  const check = codexChecks.find(c => c.id === 'CDX-005')!;

  it('fails when shell_environment_policy.inherit = "all"', async () => {
    const config = makeConfig('config.toml', {
      shell_environment_policy: { inherit: 'all' },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when inherit = "core"', async () => {
    const config = makeConfig('config.toml', {
      shell_environment_policy: { inherit: 'core' },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes when shell_environment_policy is unset', async () => {
    const result = await check.run(makeCtx([makeConfig('config.toml', { model: 'o4-mini' })]));
    expect(result.passed).toBe(true);
  });
});

describe('CDX-006: Codex Trusted Projects Too Broad', () => {
  const check = codexChecks.find(c => c.id === 'CDX-006')!;

  it('fails when trusted_projects contains "/"', async () => {
    const config = makeConfig('config.toml', { trusted_projects: ['/'] });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('fails when trusted_projects contains "~"', async () => {
    const config = makeConfig('config.toml', { trusted_projects: ['~'] });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('fails when [projects."/tmp"] trust_level = "trusted"', async () => {
    const config = makeConfig('config.toml', {
      projects: { '/tmp': { trust_level: 'trusted' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes for narrow project paths', async () => {
    const config = makeConfig('config.toml', {
      trusted_projects: ['/Users/dev/myrepo'],
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CDX-007: Codex Memory File Secret Leak', () => {
  const check = codexChecks.find(c => c.id === 'CDX-007')!;

  it('passes when no memory files exist', async () => {
    const fs = makeFs({ access: vi.fn(async () => false) });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });

  it('fails when AGENTS.md contains an Anthropic key', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('AGENTS.md')),
      readFile: vi.fn(async () => 'Use sk-ant-' + 'A'.repeat(40) + 'q9Wz1XYz for testing'),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('fails when instructions.md contains an AWS key', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('instructions.md')),
      readFile: vi.fn(async () => 'AKIAIOSFODNN7EXAMPLE\n'),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
  });

  it('passes for ordinary memory content', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      readFile: vi.fn(async () => '# Instructions\nUse npm for builds.\n'),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});

describe('CDX-008: Codex Profile Security Downgrade', () => {
  const check = codexChecks.find(c => c.id === 'CDX-008')!;

  it('fails when a profile sets approval_policy = "never" but root does not', async () => {
    const config = makeConfig('config.toml', {
      approval_policy: 'on-request',
      profiles: { yolo: { approval_policy: 'never' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('fails when a profile sets sandbox_mode = "danger-full-access" but root does not', async () => {
    const config = makeConfig('config.toml', {
      sandbox_mode: 'workspace-write',
      profiles: { yolo: { sandbox_mode: 'danger-full-access' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when a profile matches root settings', async () => {
    const config = makeConfig('config.toml', {
      approval_policy: 'on-request',
      profiles: { dev: { approval_policy: 'on-request', sandbox_mode: 'workspace-write' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('does not flag a profile that matches an already-dangerous root', async () => {
    const config = makeConfig('config.toml', {
      approval_policy: 'never',
      profiles: { same: { approval_policy: 'never' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes when no profiles are defined', async () => {
    const result = await check.run(makeCtx([makeConfig('config.toml', { model: 'o4-mini' })]));
    expect(result.passed).toBe(true);
  });
});

describe('CDX-009: Codex Unsafe Notify Command', () => {
  const check = codexChecks.find(c => c.id === 'CDX-009')!;

  it('fails when notify uses sh -c', async () => {
    const config = makeConfig('config.toml', {
      notify: ['sh', '-c', 'echo done | tee /tmp/log'],
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
    expect(result.evidence?.[0].detail).toMatch(/sh -c/);
  });

  it('fails when notify uses bash -c', async () => {
    const config = makeConfig('config.toml', {
      notify: ['bash', '-c', 'curl example.com'],
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('fails when notify command is a relative name (PATH hijack)', async () => {
    const config = makeConfig('config.toml', {
      notify: ['my-notifier', '--quiet'],
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toMatch(/PATH hijack/);
  });

  it('fails when notify references a /tmp script', async () => {
    const config = makeConfig('config.toml', {
      notify: ['/usr/bin/python3', '/tmp/notify.py'],
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toMatch(/world-writable/);
  });

  it('detects unsafe notify inside a profile', async () => {
    const config = makeConfig('config.toml', {
      notify: ['/usr/local/bin/notify'],
      profiles: {
        risky: { notify: ['sh', '-c', 'whoami'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].snippet).toMatch(/profiles.risky/);
  });

  it('passes when notify is an absolute path to a non-shell binary', async () => {
    const config = makeConfig('config.toml', {
      notify: ['/usr/local/bin/codex-notify', '--json'],
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes when notify is unset', async () => {
    const result = await check.run(makeCtx([makeConfig('config.toml', { model: 'o4-mini' })]));
    expect(result.passed).toBe(true);
  });

  it('passes when notify is an empty array', async () => {
    const result = await check.run(makeCtx([makeConfig('config.toml', { notify: [] })]));
    expect(result.passed).toBe(true);
  });
});
