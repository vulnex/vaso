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

  // g6-F2: entropy alone is not a secret — a secret-like name, or a known key format
  it('ignores high-entropy values under non-secret names, but not a known key format', async () => {
    const benign = await check.run(makeCtx([makeConfig('settings.json', {
      env: {
        USER_AGENT: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.6778.85',
        WORKDIR: '/home/dev/projects/x9Qz-Lm2v/build/out-7f3a91c2b8e4d6f0',
      },
      mcpServers: { s: { env: { SESSION_ID: 'q8Z2x7Lk3Vm9Np4Rt6Wy1Bc5Df0Gh' } } },
    })]));
    expect(benign.passed).toBe(true);
    const known = await check.run(makeCtx([makeConfig('settings.json', {
      env: { UPSTREAM: 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789' },
    })]));
    expect(known.passed).toBe(false);
    const named = await check.run(makeCtx([makeConfig('settings.json', {
      env: { SERVICE_TOKEN: 'q8Z2x7Lk3Vm9Np4Rt6Wy1Bc5Df0Gh' },
    })]));
    expect(named.passed).toBe(false);
    for (const env of [
      { MISTRAL_KEY: 'q8Z2x7Lk3Vm9Np4Rt6Wy1Bc5Df0Gh' },
      { GITLAB_PAT: 'glpat-q8Z2x7Lk3Vm9Np4Rt6Wy1B' },
      { UPSTREAM_A: 'gsk_q8Z2x7Lk3Vm9Np4Rt6Wy1Bc5Df0Gh' },
      { UPSTREAM_B: 'hf_q8Z2x7Lk3Vm9Np4Rt6Wy1Bc5Df0Gh' },
    ]) {
      expect((await check.run(makeCtx([makeConfig('settings.json', { env })]))).passed, Object.keys(env)[0]).toBe(false);
    }
  });

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

  it('passes on documentation placeholders copied from the docs', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      env: { ANTHROPIC_API_KEY: 'sk-ant-your-actual-anthropic-key-here', OPENAI_API_KEY: 'sk-...' },
    })]));
    expect(result.passed).toBe(true);
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

  it('fails when a settings.json holding an API key is world-readable', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('settings.json')),
      stat: vi.fn(async () => ({ mode: 0o664, isFile: () => true, isDirectory: () => false })),
    });
    const settings = makeConfig("/home/test/.qwen/settings.json", { env: { OPENAI_API_KEY: 'sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z' } });
    expect((await check.run(makeCtx([settings], fs))).passed).toBe(false);
  });

  it('passes a secret-free settings.json at 0644/0664 (Qwen writes it with the default umask)', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('settings.json')),
      stat: vi.fn(async () => ({ mode: 0o664, isFile: () => true, isDirectory: () => false })),
    });
    const settings = makeConfig("/home/test/.qwen/settings.json", { ui: { theme: 'Default' }, tools: { approvalMode: 'default' } });
    expect((await check.run(makeCtx([settings], fs))).passed).toBe(true);
  });

  it('still fails for a world-readable oauth_creds.json', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('oauth_creds.json')),
      stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    });
    expect((await check.run(makeCtx([], fs))).passed).toBe(false);
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

  it('passes when a deny (or ask) rule covers the same tool', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      permissions: { allow: ['Shell(*)'], deny: ['Shell(rm)'] },
    })]));
    expect(result.passed).toBe(true);
    // Bash / Shell / run_shell_command are one tool (settings.md aliases)
    expect((await check.run(makeCtx([makeConfig('settings.json', { permissions: { allow: ['Bash(*)'], ask: ['run_shell_command(git push *)'] } })]))).passed).toBe(true);
    // the Edit meta-category covers write_file
    expect((await check.run(makeCtx([makeConfig('settings.json', { permissions: { allow: ['WriteFile'], deny: ['Edit(.env)'] } })]))).passed).toBe(true);
  });

  it('fails when the only deny rule is for an unrelated tool', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {
      permissions: { allow: ['Bash(*)', 'run_shell_command'], deny: ['Read(.env)'] },
    })]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toContain('Bash(*)');
    // `*` needs at least a shell net
    expect((await check.run(makeCtx([makeConfig('settings.json', { permissions: { allow: ['*'], deny: ['WebFetch'] } })]))).passed).toBe(false);
    expect((await check.run(makeCtx([makeConfig('settings.json', { permissions: { allow: ['*'], deny: ['Bash(rm -rf *)'] } })]))).passed).toBe(true);
  });
});

describe('QC-008: approvalMode "auto" (classifier) is info (tools.approvalMode docs)', () => {
  const check = qwenCodeChecks.find(c => c.id === 'QC-008')!;
  it('reports auto as info and auto-edit as a warning', async () => {
    const auto = await check.run(makeCtx([makeConfig('settings.json', { tools: { approvalMode: 'auto' } })]));
    expect(auto.passed).toBe(false);
    expect(auto.severity).toBe('info');
    expect(auto.message).toContain('auto');
    const edit = await check.run(makeCtx([makeConfig('settings.json', { tools: { approvalMode: 'auto-edit' } })]));
    expect(edit.severity).toBe('warning');
    expect((await check.run(makeCtx([makeConfig('settings.json', { tools: { approvalMode: 'default' } })]))).passed).toBe(true);
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

  it('flags OpenRouter key in QWEN.md', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('QWEN.md')),
      readFile: vi.fn(async () => 'creds: sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
  });

  // Qwen Code never reads ~/.qwen/memory.md (deep test 2026-11-09) — unless
  // context.fileName names it
  it('reads memory.md only when context.fileName names it', async () => {
    const access = vi.fn(async () => true);
    const readFile = vi.fn(async () => '# notes\n');
    await check.run(makeCtx([], makeFs({ access, readFile })));
    expect(readFile.mock.calls.map(c => String(c[0]))).not.toContainEqual(expect.stringMatching(/memory\.md$/));
    readFile.mockClear();
    await check.run(makeCtx([makeConfig('settings.json', { context: { fileName: 'memory.md' } })], makeFs({ access, readFile })));
    expect(readFile.mock.calls.map(c => String(c[0]))).toContainEqual(expect.stringMatching(/memory\.md$/));
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

  // dt20 g6-F1/F2
  it('QC-001 judges secret-named keys by format and randomness; public values and ARNs pass', async () => {
    const result = await byId('QC-001').run(makeCtx([makeConfig('settings.json', {
      env: {
        GITLAB_TOKEN: 'glpat-Ab3De5Fg7Hj9Kl1Mn3Pq',
        SERVICE_TOKEN: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b',
        SSH_PUBLIC_KEY: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGq8vJ3kLm9Pq2Rs5Tv8Wy1Ab4Cd6Ef0GhJkLmNoPqRs alice@laptop',
        DB_SECRET_ARN: 'arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf',
      },
      modelProviders: { openai: [{ apiKey: '3f9a1c7e2b8d4f6a0c5e9b1d7f3a8c2e' }] },
    })]));
    expect(result.evidence?.map(e => e.snippet.split('=')[0])).toEqual([
      'env.GITLAB_TOKEN', 'env.SERVICE_TOKEN', 'modelProviders.openai[0].apiKey',
    ]);
  });

  it('QC-005 flags only truly broad rules — bare Bash, *, Bash(*), Bash(* *) — including legacy tools.allowed', async () => {
    for (const allow of [['Bash'], ['*'], ['Bash(*)'], ['Shell(* *)'], ['run_shell_command']]) {
      const result = await byId('QC-005').run(makeCtx([makeConfig('settings.json', { permissions: { allow } })]));
      expect(result.passed, allow[0]).toBe(false);
    }
    const legacy = await byId('QC-005').run(makeCtx([makeConfig('settings.json', { tools: { allowed: ['Bash'] } })]));
    expect(legacy.passed).toBe(false);
    expect(legacy.evidence?.[0].snippet).toMatch(/^tools\.allowed has 1 broad rule/);
    const both = await byId('QC-005').run(makeCtx([makeConfig('settings.json', { permissions: { allow: ['Bash(*)'] }, tools: { allowed: ['*'] } })]));
    expect(both.evidence?.[0].snippet).toMatch(/^permissions\.allow and tools\.allowed has 2 broad rule/);
    const narrow = await byId('QC-005').run(makeCtx([makeConfig('settings.json', {
      permissions: { allow: ['Shell(git status)', 'Bash(git *)', 'Bash(npm run *)', 'Read', 'Read(**)'] },
    })]));
    expect(narrow.passed).toBe(true);
  });

  it('QC-005 counts a shell, interpreter or wrapper prefix as broad (it runs anything it is given)', async () => {
    for (const rule of ['Bash(python3 *)', 'Shell(bash -c *)', 'run_shell_command(env *)', 'Bash(node:*)', 'Bash(/usr/bin/python3.12 *)']) {
      const result = await byId('QC-005').run(makeCtx([makeConfig('settings.json', { permissions: { allow: [rule] } })]));
      expect(result.passed, rule).toBe(false);
    }
    // a non-shell tool's specifier is a path, not a command
    expect((await byId('QC-005').run(makeCtx([makeConfig('settings.json', { permissions: { allow: ['Edit(python3/*)', 'WebFetch(node.example.com)'] } })]))).passed).toBe(true);
  });

  it('QC-005 counts legacy tools.exclude as a deny net — for the tool it excludes', async () => {
    const result = await byId('QC-005').run(makeCtx([makeConfig('settings.json', {
      permissions: { allow: ['Bash'] }, tools: { exclude: ['run_shell_command(rm)'] },
    })]));
    expect(result.passed).toBe(true);
    const unrelated = await byId('QC-005').run(makeCtx([makeConfig('settings.json', {
      permissions: { allow: ['Bash'] }, tools: { exclude: ['write_file'] },
    })]));
    expect(unrelated.passed).toBe(false);
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
