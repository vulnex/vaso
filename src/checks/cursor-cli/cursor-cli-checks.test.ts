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
    expect(cursorCliChecks).toHaveLength(14);
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

describe('CUR-011: Hooks Fail-Open', () => {
  const check = cursorCliChecks.find(c => c.id === 'CUR-011')!;

  it('flags hook commands without failClosed', async () => {
    const result = await check.run(makeCtx([makeConfig('/home/test/.cursor/hooks.json', {
      version: 1,
      hooks: { beforeShellExecution: [{ command: '/usr/local/bin/guard.sh' }] },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes fail-closed hooks and configs without hooks', async () => {
    const result = await check.run(makeCtx([makeConfig('/home/test/.cursor/hooks.json', {
      hooks: { beforeShellExecution: [{ command: 'guard.sh', failClosed: true }] },
    }), makeConfig('/home/test/.cursor/cli-config.json', {})]));
    expect(result.passed).toBe(true);
  });

  it('ignores observational hooks, which gate nothing (cursor.com/docs/agent/hooks)', async () => {
    const result = await check.run(makeCtx([makeConfig('/home/test/.cursor/hooks.json', {
      version: 1,
      hooks: {
        afterFileEdit: [{ command: './hooks/format.sh' }],
        sessionStart: [{ command: './hooks/session-init.sh' }],
        stop: [{ command: 'bun run .cursor/hooks/track-stop.ts --stop' }],
      },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('CUR-012: Workspace Trust Disabled', () => {
  const check = cursorCliChecks.find(c => c.id === 'CUR-012')!;

  it('flags IDE settings without workspace trust enabled', async () => {
    const result = await check.run(makeCtx([makeConfig('/home/test/.config/Cursor/User/settings.json', {
      'window.commandCenter': 1,
    })]));
    expect(result.passed).toBe(false);
  });

  it('flags explicit false', async () => {
    const result = await check.run(makeCtx([makeConfig('/home/test/.config/Cursor/User/settings.json', {
      'security.workspace.trust.enabled': false,
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes when trust enabled', async () => {
    const result = await check.run(makeCtx([makeConfig('/home/test/.config/Cursor/User/settings.json', {
      'security.workspace.trust.enabled': true,
    })]));
    expect(result.passed).toBe(true);
  });

  it('passes when no IDE settings present (CLI-only install)', async () => {
    const result = await check.run(makeCtx([makeConfig('/home/test/.cursor/cli-config.json', {})]));
    expect(result.passed).toBe(true);
  });
});

describe('CUR-013: Session Database Permissions', () => {
  const check = cursorCliChecks.find(c => c.id === 'CUR-013')!;

  it('flags world-readable state.vscdb', async () => {
    const fs = makeFs({
      stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0]?.detail).toContain('accessToken');
  });

  it('passes 0600 state.vscdb', async () => {
    const fs = makeFs({
      stat: vi.fn(async () => ({ mode: 0o600, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });

  it('passes when db absent', async () => {
    const fs = makeFs({
      stat: vi.fn(async () => { throw new Error('ENOENT'); }),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});

describe('CUR-014: Auto-Run Instructions Too Broad', () => {
  const check = cursorCliChecks.find(c => c.id === 'CUR-014')!;

  it('flags blanket allow instructions', async () => {
    const result = await check.run(makeCtx([makeConfig('/home/test/.cursor/permissions.json', {
      autoRun: { allow_instructions: ['run any command'], block_instructions: ['rm'] },
    })]));
    expect(result.passed).toBe(false);
  });

  it('flags dangerous command grants and missing block list', async () => {
    const result = await check.run(makeCtx([makeConfig('/home/test/.cursor/permissions.json', {
      autoRun: { allow_instructions: ['allow curl requests'] },
    })]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.length).toBeGreaterThanOrEqual(2);
  });

  it('passes scoped instructions with a block list', async () => {
    const result = await check.run(makeCtx([makeConfig('/home/test/.cursor/permissions.json', {
      autoRun: {
        allow_instructions: ['npm test', 'git status'],
        block_instructions: ['anything touching credentials'],
      },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('deep-test 2026-10-15 regressions', () => {
  const byId = (id: string) => cursorCliChecks.find(c => c.id === id)!;

  it('CUR-002 flags the documented approvalMode "unrestricted"', async () => {
    const result = await byId('CUR-002').run(makeCtx([makeConfig('/home/test/.cursor/cli-config.json', { approvalMode: 'unrestricted' })]));
    expect(result.passed).toBe(false);
    const safe = await byId('CUR-002').run(makeCtx([makeConfig('/home/test/.cursor/cli-config.json', { approvalMode: 'allowlist' })]));
    expect(safe.passed).toBe(true);
  });

  it('CUR-006 compares the parsed host (localhost.evil.com is remote)', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      readFile: vi.fn(async () => JSON.stringify({ mcpServers: { a: { url: 'http://localhost.evil.com/mcp' }, b: { url: 'http://[::1]:3000/mcp' } } })),
    });
    const result = await byId('CUR-006').run(makeCtx([], fs));
    expect(result.evidence?.map(e => e.snippet)).toEqual(['mcpServers.a.url = http://localhost.evil.com/mcp']);
  });

  it('CUR-013 leaves the user-level state.vscdb to the user install', async () => {
    const fs = makeFs({ stat: vi.fn(async () => ({ mode: 0o100644, isFile: () => true, isDirectory: () => false })) });
    const ctx = makeCtx([], fs);
    const project = { ...ctx, installation: { ...ctx.installation, installDir: '/work/app/.cursor', profile: 'project' } };
    const result = await byId('CUR-013').run(project);
    expect(result.passed).toBe(true);
    expect(result.evidence ?? []).toHaveLength(0);
  });
});
