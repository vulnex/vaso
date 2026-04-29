import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { cursorCliChecks } from './index.js';

function makeConfig(filePath: string, data: Record<string, unknown>): ParsedConfig {
  return { raw: '', format: 'json', filePath, data };
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
    agent: 'cursor-cli',
    installDir: '/home/test/.cursor',
    configFiles: configs,
  };
  return { installation, configs, platform: 'linux', fs: fs ?? makeFs() };
}

describe('Cursor CLI checks', () => {
  it('exports 10 checks with correct shape', () => {
    expect(cursorCliChecks).toHaveLength(10);
    for (const check of cursorCliChecks) {
      expect(check.category).toBe('coding-agent');
      expect(check.supportedAgents).toContain('cursor-cli');
      expect(check.id).toMatch(/^CUR-0\d{2}$/);
    }
  });
});

describe('CUR-001: Sandbox Disabled', () => {
  const check = cursorCliChecks.find(c => c.id === 'CUR-001')!;

  it('fails on sandbox.mode=disabled (the real config we saw)', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      sandbox: { mode: 'disabled', networkAccess: 'user_config_with_defaults' },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes on enabled sandbox', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      sandbox: { mode: 'enabled' },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('CUR-002: Unsafe Approval', () => {
  const check = cursorCliChecks.find(c => c.id === 'CUR-002')!;

  it('fails on approvalMode=yolo', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', { approvalMode: 'yolo' })]));
    expect(result.passed).toBe(false);
  });

  it('passes on allowlist', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', { approvalMode: 'allowlist' })]));
    expect(result.passed).toBe(true);
  });
});

describe('CUR-003: Overbroad Shell', () => {
  const check = cursorCliChecks.find(c => c.id === 'CUR-003')!;

  it('fails on Shell(*)', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      permissions: { allow: ['Shell(*)'], deny: [] },
    })]));
    expect(result.passed).toBe(false);
  });

  it('fails on Shell(bash)', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      permissions: { allow: ['Shell(bash)'], deny: [] },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes on Shell(git) (the real config we saw also had Shell(ls))', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      permissions: { allow: ['Shell(git)', 'Shell(ls)'], deny: [] },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('CUR-004: Config Permissions', () => {
  const check = cursorCliChecks.find(c => c.id === 'CUR-004')!;

  it('fails when cli-config.json is world-readable', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('cli-config.json')),
      stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
  });

  it('passes when 0600', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('cli-config.json')),
      stat: vi.fn(async () => ({ mode: 0o600, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});

describe('CUR-005: Deny vs Allow', () => {
  const check = cursorCliChecks.find(c => c.id === 'CUR-005')!;

  it('fails when allow has Write(*) and deny is empty', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      permissions: { allow: ['Write(*)'], deny: [] },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes when deny is non-empty', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      permissions: { allow: ['Write(*)'], deny: ['Write(**/*.env)'] },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('CUR-006: MCP HTTP', () => {
  const check = cursorCliChecks.find(c => c.id === 'CUR-006')!;

  it('fails when mcp.json has http:// server', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('mcp.json')),
      readFile: vi.fn(async () => JSON.stringify({
        mcpServers: { foo: { url: 'http://api.example.com/mcp' } },
      })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
  });

  it('passes when no mcp.json', async () => {
    const fs = makeFs({
      access: vi.fn(async () => false),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});

describe('CUR-007: Privacy Mode', () => {
  const check = cursorCliChecks.find(c => c.id === 'CUR-007')!;

  it('fails when ghostMode is false', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      privacyCache: { ghostMode: false, privacyMode: 1 },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes when ghostMode true and privacyMode 1 (the real config we saw)', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      privacyCache: { ghostMode: true, privacyMode: 1 },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('CUR-008: Sandbox Network', () => {
  const check = cursorCliChecks.find(c => c.id === 'CUR-008')!;

  it('fails when networkAccess=unrestricted', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      sandbox: { networkAccess: 'unrestricted' },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes on user_config_with_defaults', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      sandbox: { networkAccess: 'user_config_with_defaults' },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('CUR-009: Overbroad Paths', () => {
  const check = cursorCliChecks.find(c => c.id === 'CUR-009')!;

  it('fails on Write(*)', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      permissions: { allow: ['Write(*)'], deny: [] },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes on scoped paths', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      permissions: { allow: ['Write(src/**)', 'Read(src/**)'], deny: [] },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('CUR-010: Attribution', () => {
  const check = cursorCliChecks.find(c => c.id === 'CUR-010')!;

  it('fails when attributeCommitsToAgent=true (the real config we saw)', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      attribution: { attributeCommitsToAgent: true, attributePRsToAgent: true },
    })]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('info');
  });

  it('passes when attribution is off', async () => {
    const result = await check.run(makeCtx([makeConfig('cli-config.json', {
      attribution: { attributeCommitsToAgent: false, attributePRsToAgent: false },
    })]));
    expect(result.passed).toBe(true);
  });
});
