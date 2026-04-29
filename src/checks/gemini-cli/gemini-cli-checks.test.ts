import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { geminiCliChecks } from './index.js';

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
    agent: 'gemini-cli',
    installDir: '/home/test/.gemini',
    configFiles: configs,
  };
  return { installation, configs, platform: 'linux', fs: fs ?? makeFs() };
}

describe('Gemini CLI checks', () => {
  it('exports 10 checks', () => {
    expect(geminiCliChecks).toHaveLength(10);
  });

  it('all checks have coding-agent category and supportedAgents', () => {
    for (const check of geminiCliChecks) {
      expect(check.category).toBe('coding-agent');
      expect(check.supportedAgents).toContain('gemini-cli');
    }
  });

  it('all check IDs match GEM-0NN pattern', () => {
    for (const check of geminiCliChecks) {
      expect(check.id).toMatch(/^GEM-0\d{2}$/);
    }
  });
});

describe('GEM-001: Plaintext API Key', () => {
  const check = geminiCliChecks.find(c => c.id === 'GEM-001')!;

  it('flags high-entropy value under env.API_KEY', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      env: { GEMINI_API_KEY: 'AIzaSyD1234567890abcdefghijklmnopqrstuvwxyz' },
    })]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when env value is a $-reference', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      env: { GEMINI_API_KEY: '$GEMINI_API_KEY' },
    })]));
    expect(result.passed).toBe(true);
  });

  it('flags MCP server env values', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      mcpServers: {
        github: { env: { GITHUB_TOKEN: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' } },
      },
    })]));
    expect(result.passed).toBe(false);
  });
});

describe('GEM-002: Credential Permissions', () => {
  const check = geminiCliChecks.find(c => c.id === 'GEM-002')!;

  it('fails when oauth_creds.json is world-readable', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('oauth_creds.json')),
      stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
  });

  it('passes when files are 0600', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('settings.json')),
      stat: vi.fn(async () => ({ mode: 0o600, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});

describe('GEM-003: Overbroad Tools Allow', () => {
  const check = geminiCliChecks.find(c => c.id === 'GEM-003')!;

  it('fails on bare run_shell_command', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      tools: { allowed: ['run_shell_command'] },
    })]));
    expect(result.passed).toBe(false);
  });

  it('fails on run_shell_command(bash)', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      tools: { allowed: ['run_shell_command(bash)'] },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes on specific allowed commands', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      tools: { allowed: ['run_shell_command(git status)', 'run_shell_command(npm test)'] },
    })]));
    expect(result.passed).toBe(true);
  });

  it('does not flag entries also in confirmationRequired', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      tools: {
        allowed: ['run_shell_command(bash)'],
        confirmationRequired: ['run_shell_command(bash)'],
      },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('GEM-004: YOLO Mode Guard', () => {
  const check = geminiCliChecks.find(c => c.id === 'GEM-004')!;

  it('fails when security.disableYoloMode is explicitly false', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      security: { disableYoloMode: false },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes when not set (default behavior)', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {})]));
    expect(result.passed).toBe(true);
  });

  it('passes when disableYoloMode is true', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      security: { disableYoloMode: true },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('GEM-005: Sandbox Disabled', () => {
  const check = geminiCliChecks.find(c => c.id === 'GEM-005')!;

  it('fails when tools.sandbox is false', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      tools: { sandbox: false },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes when tools.sandbox is true or "docker"', async () => {
    const r1 = await check.run(makeCtx([makeConfig('settings.json', { tools: { sandbox: true } })]));
    const r2 = await check.run(makeCtx([makeConfig('settings.json', { tools: { sandbox: 'docker' } })]));
    expect(r1.passed).toBe(true);
    expect(r2.passed).toBe(true);
  });
});

describe('GEM-006: Sandbox Network Access', () => {
  const check = geminiCliChecks.find(c => c.id === 'GEM-006')!;

  it('fails when sandboxNetworkAccess is true', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      tools: { sandboxNetworkAccess: true },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes when not set', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {})]));
    expect(result.passed).toBe(true);
  });
});

describe('GEM-007: Unpinned MCP Server', () => {
  const check = geminiCliChecks.find(c => c.id === 'GEM-007')!;

  it('fails on npx without version pin', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      mcpServers: {
        foo: { command: 'npx', args: ['@some/server'] },
      },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes on pinned package', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      mcpServers: {
        foo: { command: 'npx', args: ['@some/server@1.2.3'] },
      },
    })]));
    expect(result.passed).toBe(true);
  });

  it('ignores non-package-runner commands', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      mcpServers: {
        foo: { command: '/usr/local/bin/myserver' },
      },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('GEM-008: MCP HTTP Transport', () => {
  const check = geminiCliChecks.find(c => c.id === 'GEM-008')!;

  it('fails on http:// URL', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      mcpServers: {
        foo: { httpUrl: 'http://api.example.com/mcp' },
      },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes on https://', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      mcpServers: {
        foo: { httpUrl: 'https://api.example.com/mcp' },
      },
    })]));
    expect(result.passed).toBe(true);
  });

  it('ignores localhost http://', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      mcpServers: {
        foo: { httpUrl: 'http://localhost:8080/mcp' },
      },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('GEM-009: Auto-Edit Mode', () => {
  const check = geminiCliChecks.find(c => c.id === 'GEM-009')!;

  it('fails when defaultApprovalMode is auto_edit', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      general: { defaultApprovalMode: 'auto_edit' },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes on default', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      general: { defaultApprovalMode: 'default' },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('GEM-010: Memory File Secrets', () => {
  const check = geminiCliChecks.find(c => c.id === 'GEM-010')!;

  it('flags OpenRouter key in memory.md', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('memory.md')),
      readFile: vi.fn(async () => 'My key: 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'),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
  });

  it('passes on clean memory files', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      readFile: vi.fn(async () => '# Project notes\n\nUse git for version control.\n'),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});
