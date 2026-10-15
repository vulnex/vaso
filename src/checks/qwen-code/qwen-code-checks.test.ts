import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { qwenCodeChecks } from './index.js';

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
    agent: 'qwen-code',
    installDir: '/home/test/.qwen',
    configFiles: configs,
  };
  return { installation, configs, platform: 'linux', fs: fs ?? makeFs() };
}

describe('Qwen Code checks', () => {
  it('exports 10 checks with correct shape', () => {
    expect(qwenCodeChecks).toHaveLength(10);
    for (const check of qwenCodeChecks) {
      expect(check.category).toBe('coding-agent');
      expect(check.supportedAgents).toContain('qwen-code');
      expect(check.id).toMatch(/^QC-0\d{2}$/);
    }
  });
});

describe('QC-001: Plaintext API Key', () => {
  const check = qwenCodeChecks.find(c => c.id === 'QC-001')!;

  it('flags OpenRouter key under env (the real-world leak)', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      env: { OPENROUTER_API_KEY: 'sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' },
    })]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('flags inline modelProviders[].apiKey', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      modelProviders: { openai: [{ id: 'gpt', apiKey: 'sk-abcdefghijklmnopqrstuvwxyz0123456789' }] },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes when env values are $-references', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      env: { OPENROUTER_API_KEY: '$OPENROUTER_API_KEY' },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('QC-002: Credential Permissions', () => {
  const check = qwenCodeChecks.find(c => c.id === 'QC-002')!;

  it('fails when settings.json is world-readable (the real config we saw)', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('settings.json')),
      stat: vi.fn(async () => ({ mode: 0o664, isFile: () => true, isDirectory: () => false })),
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

describe('QC-003: YOLO Mode', () => {
  const check = qwenCodeChecks.find(c => c.id === 'QC-003')!;

  it('fails on approvalMode=yolo', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', { approvalMode: 'yolo' })]));
    expect(result.passed).toBe(false);
  });

  it('passes on approvalMode=default', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', { approvalMode: 'default' })]));
    expect(result.passed).toBe(true);
  });
});

describe('QC-004: MCP Trust', () => {
  const check = qwenCodeChecks.find(c => c.id === 'QC-004')!;

  it('fails when an MCP server has trust:true', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      mcpServers: { foo: { command: 'npx', args: ['x'], trust: true } },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes when no trust:true is set', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      mcpServers: { foo: { command: 'npx' } },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('QC-005: Deny vs Allow', () => {
  const check = qwenCodeChecks.find(c => c.id === 'QC-005')!;

  it('fails when allow has a wildcard and deny is empty', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      permissions: { allow: ['Shell(*)'], deny: [] },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes when deny is non-empty', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      permissions: { allow: ['Shell(*)'], deny: ['Shell(rm)'] },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('QC-006: Unpinned MCP', () => {
  const check = qwenCodeChecks.find(c => c.id === 'QC-006')!;

  it('fails on npx without pin', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      mcpServers: { foo: { command: 'npx', args: ['@some/server'] } },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes when pinned', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      mcpServers: { foo: { command: 'npx', args: ['@some/server@1.2.3'] } },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('QC-007: MCP HTTP', () => {
  const check = qwenCodeChecks.find(c => c.id === 'QC-007')!;

  it('fails on http://', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      mcpServers: { foo: { httpUrl: 'http://api.example.com/mcp' } },
    })]));
    expect(result.passed).toBe(false);
  });

  it('passes on https://', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      mcpServers: { foo: { httpUrl: 'https://api.example.com/mcp' } },
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('QC-008: Auto-Edit', () => {
  const check = qwenCodeChecks.find(c => c.id === 'QC-008')!;

  it('fails on approvalMode=auto-edit', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', { approvalMode: 'auto-edit' })]));
    expect(result.passed).toBe(false);
  });

  it('passes on default', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', { approvalMode: 'default' })]));
    expect(result.passed).toBe(true);
  });
});

describe('QC-009: Telemetry Prompts', () => {
  const check = qwenCodeChecks.find(c => c.id === 'QC-009')!;

  it('fails when telemetry.logPrompts is true', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', { telemetry: { logPrompts: true } })]));
    expect(result.passed).toBe(false);
  });

  it('passes when not enabled', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {})]));
    expect(result.passed).toBe(true);
  });
});

describe('QC-010: Memory Secrets', () => {
  const check = qwenCodeChecks.find(c => c.id === 'QC-010')!;

  it('flags OpenRouter key in memory.md', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('memory.md')),
      readFile: vi.fn(async () => 'creds: sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
  });

  it('passes on clean files', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      readFile: vi.fn(async () => '# Notes\n\nUse python for scripts.'),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});

describe('deep-test 2026-10-15 regressions', () => {
  const byId = (id: string) => qwenCodeChecks.find(c => c.id === id)!;

  it('QC-003 reads tools.approvalMode (current schema) and keeps the top-level fallback', async () => {
    const current = await byId('QC-003').run(makeCtx([makeConfig('settings.json', { tools: { approvalMode: 'yolo' } })]));
    expect(current.passed).toBe(false);
    expect(current.evidence?.[0].snippet).toBe('tools.approvalMode = "yolo"');
    const legacy = await byId('QC-003').run(makeCtx([makeConfig('settings.json', { approvalMode: 'yolo' })]));
    expect(legacy.passed).toBe(false);
  });

  it('QC-008 reads tools.approvalMode: auto-edit', async () => {
    const result = await byId('QC-008').run(makeCtx([makeConfig('settings.json', { tools: { approvalMode: 'auto-edit' } })]));
    expect(result.passed).toBe(false);
  });

  it('QC-001 flags the deprecated security.auth.apiKey and MCP headers', async () => {
    const result = await byId('QC-001').run(makeCtx([makeConfig('settings.json', {
      security: { auth: { apiKey: 'sk-abcdefghijklmnopqrstuvwxyz0123456789' } },
      mcpServers: { r: { httpUrl: 'https://mcp.example.com', headers: { Authorization: 'Bearer sk-ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210' } } },
    })]));
    expect(result.evidence?.map(e => e.snippet.split('=')[0])).toEqual([
      'security.auth.apiKey', 'mcpServers.r.headers.Authorization',
    ]);
  });

  it('QC-005 flags only truly broad rules — bare Bash, *, Bash(*), Bash(* *) — including legacy tools.allowed', async () => {
    for (const allow of [['Bash'], ['*'], ['Bash(*)'], ['Shell(* *)'], ['run_shell_command']]) {
      const result = await byId('QC-005').run(makeCtx([makeConfig('settings.json', { permissions: { allow } })]));
      expect(result.passed, allow[0]).toBe(false);
    }
    const legacy = await byId('QC-005').run(makeCtx([makeConfig('settings.json', { tools: { allowed: ['Bash'] } })]));
    expect(legacy.passed).toBe(false);
    const narrow = await byId('QC-005').run(makeCtx([makeConfig('settings.json', {
      permissions: { allow: ['Shell(git status)', 'Bash(git *)', 'Bash(npm run *)', 'Read', 'Read(**)'] },
    })]));
    expect(narrow.passed).toBe(true);
  });

  it('QC-005 counts legacy tools.exclude as a deny net', async () => {
    const result = await byId('QC-005').run(makeCtx([makeConfig('settings.json', {
      permissions: { allow: ['Bash'] }, tools: { exclude: ['write_file'] },
    })]));
    expect(result.passed).toBe(true);
  });

  it('QC-007 compares the parsed host (localhost.evil.com is remote)', async () => {
    const evil = await byId('QC-007').run(makeCtx([makeConfig('settings.json', { mcpServers: { s: { url: 'http://localhost.evil.com/mcp' } } })]));
    expect(evil.passed).toBe(false);
    const local = await byId('QC-007').run(makeCtx([makeConfig('settings.json', { mcpServers: { s: { url: 'http://localhost:8080/mcp' } } })]));
    expect(local.passed).toBe(true);
  });

  it('QC-010 scans QWEN.md and a configured context.fileName', async () => {
    const read: string[] = [];
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('/QWEN.md') || p.endsWith('/CONTEXT.md')),
      readFile: vi.fn(async (p: string) => {
        read.push(p);
        return 'key sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
      }),
    });
    const result = await byId('QC-010').run(makeCtx([makeConfig('settings.json', { context: { fileName: ['CONTEXT.md', '../escape.md'] } })], fs));
    expect(result.passed).toBe(false);
    expect(read).toEqual(['/home/test/.qwen/QWEN.md', '/home/test/.qwen/CONTEXT.md']);
  });
});
