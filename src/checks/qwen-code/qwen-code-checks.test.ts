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
      env: { OPENROUTER_API_KEY: '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' },
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
      readFile: vi.fn(async () => 'creds: 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'),
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
