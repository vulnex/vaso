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
  it('exports 11 checks', () => {
    expect(geminiCliChecks).toHaveLength(11);
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

  it('ignores a secret-free settings.json at 0644 (Gemini writes it group-readable) but not one holding a key', async () => {
    const settings = '/home/test/.gemini/settings.json';
    const fs = makeFs({
      access: vi.fn(async (p: string) => p === settings),
      stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    });
    expect((await check.run(makeCtx([makeConfig(settings, { ui: { theme: 'GitHub' } })], fs))).passed).toBe(true);
    const withKey = makeConfig(settings, { env: { GEMINI_API_KEY: 'AIzaSyD1x2Y3z4W5v6U7t8S9r0QpOnMlKjIhGfE' } });
    expect((await check.run(makeCtx([withKey], fs))).passed).toBe(false);
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
      readFile: vi.fn(async () => 'My key: sk-or-v1-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'),
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

describe('GEM-011: Trusted Folder Too Broad', () => {
  const check = geminiCliChecks.find(c => c.id === 'GEM-011')!;

  it('flags home directory with TRUST_FOLDER', async () => {
    const result = await check.run(makeCtx([makeConfig('/home/test/.gemini/trustedFolders.json', {
      '/home/test': 'TRUST_FOLDER',
    })]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0]?.detail).toContain('home directory');
  });

  it('passes specific project folders and non-trust levels', async () => {
    const result = await check.run(makeCtx([makeConfig('/home/test/.gemini/trustedFolders.json', {
      '/home/test/projects/app': 'TRUST_FOLDER',
      '/tmp': 'DO_NOT_TRUST',
    })]));
    expect(result.passed).toBe(true);
  });

  it('reads ~/.gemini/trustedFolders.json itself (the adapter does not load it)', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p === '/home/test/.gemini/trustedFolders.json'),
      readFile: vi.fn(async () => JSON.stringify({ '/': 'TRUST_FOLDER', '/home/test/app': 'TRUST_FOLDER' })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
    expect(result.evidence).toHaveLength(1);
    expect(result.evidence?.[0].file).toBe('/home/test/.gemini/trustedFolders.json');
  });

  it('ignores non-trustedFolders config files', async () => {
    const result = await check.run(makeCtx([makeConfig('/home/test/.gemini/settings.json', {
      '/': 'TRUST_FOLDER',
    })]));
    expect(result.passed).toBe(true);
  });
});

describe('deep-test 2026-10-15 regressions', () => {
  const byId = (id: string) => geminiCliChecks.find(c => c.id === id)!;

  it('GEM-001 flags a literal bearer token in mcpServers.*.headers', async () => {
    const result = await byId('GEM-001').run(makeCtx([makeConfig('settings.json', {
      mcpServers: { remote: { httpUrl: 'https://mcp.example.com', headers: { Authorization: 'Bearer ghp_abcdefghijklmnopqrstuvwxyz0123456789' } } },
    })]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].snippet).toContain('mcpServers.remote.headers.Authorization');
  });

  it('GEM-001 passes a $-referenced header value', async () => {
    const result = await byId('GEM-001').run(makeCtx([makeConfig('settings.json', {
      mcpServers: { remote: { headers: { Authorization: 'Bearer $MCP_TOKEN' } } },
    })]));
    expect(result.passed).toBe(true);
  });

  it('GEM-003 flags an MCP server with trust: true (skips tool-call confirmation)', async () => {
    const result = await byId('GEM-003').run(makeCtx([makeConfig('settings.json', {
      mcpServers: { fs: { command: 'node', args: ['server.js'], trust: true }, other: { command: 'x' } },
    })]));
    expect(result.passed).toBe(false);
    expect(result.evidence).toHaveLength(1);
    expect(result.evidence?.[0].snippet).toBe('mcpServers.fs.trust = true');
  });

  it('GEM-008 compares the parsed host — loopback-looking remote hosts are flagged', async () => {
    for (const url of ['http://localhost.evil.com/mcp', 'http://127.0.0.1.nip.io/mcp']) {
      const result = await byId('GEM-008').run(makeCtx([makeConfig('settings.json', { mcpServers: { s: { httpUrl: url } } })]));
      expect(result.passed, url).toBe(false);
    }
    for (const url of ['http://localhost:3000/mcp', 'http://127.0.0.2/mcp', 'http://[::1]:8080/mcp']) {
      const result = await byId('GEM-008').run(makeCtx([makeConfig('settings.json', { mcpServers: { s: { url } } })]));
      expect(result.passed, url).toBe(true);
    }
  });

  it('GEM-009 flags legacy tools.approvalMode: auto_edit (migrated at load)', async () => {
    const result = await byId('GEM-009').run(makeCtx([makeConfig('settings.json', { tools: { approvalMode: 'auto_edit' } })]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].snippet).toBe('tools.approvalMode = "auto_edit"');
  });

  it('GEM-009 lets general.defaultApprovalMode win over the legacy key', async () => {
    const result = await byId('GEM-009').run(makeCtx([makeConfig('settings.json', {
      general: { defaultApprovalMode: 'default' }, tools: { approvalMode: 'auto_edit' },
    })]));
    expect(result.passed).toBe(true);
  });

  it('GEM-011 resolves TRUST_PARENT to the parent folder ("~/code" trusts $HOME)', async () => {
    const result = await byId('GEM-011').run(makeCtx([makeConfig('/home/test/.gemini/trustedFolders.json', {
      '~/code': 'TRUST_PARENT',
      '/home/test/code/app': 'TRUST_PARENT',
    })]));
    expect(result.passed).toBe(false);
    expect(result.evidence).toHaveLength(1);
    expect(result.evidence?.[0].detail).toContain('home directory');
  });

  it('GEM-011 reads the file named by GEMINI_CLI_TRUSTED_FOLDERS_PATH', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p === '/etc/trust.json'),
      readFile: vi.fn(async () => JSON.stringify({ '/': 'TRUST_FOLDER' })),
      getEnv: (k: string) => (k === 'GEMINI_CLI_TRUSTED_FOLDERS_PATH' ? '/etc/trust.json' : undefined),
    } as Partial<FSProvider>);
    const result = await byId('GEM-011').run(makeCtx([], fs));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].file).toBe('/etc/trust.json');
  });
});
