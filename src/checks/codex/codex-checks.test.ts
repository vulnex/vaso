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
    getEnv: vi.fn(() => undefined),
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
  it('exports 10 checks', () => {
    expect(codexChecks).toHaveLength(10);
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
  it('is info for the documented read-only non-interactive preset (never + read-only)', async () => {
    const result = await check.run(makeCtx([makeConfig('config.toml', { approval_policy: 'never', sandbox_mode: 'read-only' })]));
    expect(result.severity).toBe('info');
    const ws = await check.run(makeCtx([makeConfig('config.toml', { approval_policy: 'never', sandbox_mode: 'workspace-write' })]));
    expect(ws.severity).toBe('critical');
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
  it('names network access, not a disabled sandbox, when only network_access is on', async () => {
    const result = await check.run(makeCtx([makeConfig('config.toml', { sandbox_workspace_write: { network_access: true } })]));
    expect(result.severity).toBe('warning');
    expect(result.message).toMatch(/network access/);
    expect(result.message).not.toMatch(/disabled/);
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

  it('is info (the vendor default, inherit = "all") when shell_environment_policy is unset', async () => {
    const result = await check.run(makeCtx([makeConfig('config.toml', { model: 'o4-mini' })]));
    expect(result.severity).toBe('info');
  });
  it('is info when inherit = "all" filters secrets (official config sample)', async () => {
    for (const policy of [
      { inherit: 'all', ignore_default_excludes: false },
      { inherit: 'all', include_only: ['PATH', 'HOME'] },
    ]) {
      const result = await check.run(makeCtx([makeConfig('config.toml', { shell_environment_policy: policy })]));
      expect(result.severity).toBe('info');
    }
    const wild = await check.run(makeCtx([makeConfig('config.toml', { shell_environment_policy: { inherit: 'all', include_only: ['*'] } })]));
    expect(wild.severity).toBe('critical');
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

  it('uses ctx.fs.homedir() (not the scanner host) when matching $HOME as a broad path', async () => {
    const config = makeConfig('config.toml', {
      trusted_projects: ['/snap/remote-user'],
    });
    const fs = makeFs({ homedir: () => '/snap/remote-user' });
    const result = await check.run(makeCtx([config], fs));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toContain('covers the entire home directory');
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

  // ~/.codex/instructions.md: legacy TypeScript CLI (< 0.20.0) only
  it('fails when instructions.md contains an AWS key for the legacy TypeScript CLI', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('instructions.md')),
      readFile: vi.fn(async () => 'AKIAZ7QX4M2PLR5TNW3B\n'),
    });
    const ctx = makeCtx([], fs);
    ctx.installation.version = '0.1.2505172129';
    const result = await check.run(ctx);
    expect(result.passed).toBe(false);
  });

  it('ignores instructions.md for the Rust CLI and an unknown version', async () => {
    for (const version of ['0.20.0', '0.167.0', undefined]) {
      const readFile = vi.fn(async () => 'AKIAZ7QX4M2PLR5TNW3B\n');
      const ctx = makeCtx([], makeFs({ access: vi.fn(async (p: string) => p.endsWith('instructions.md')), readFile }));
      ctx.installation.version = version;
      const result = await check.run(ctx);
      expect(result.passed).toBe(true);
      expect(readFile).not.toHaveBeenCalled();
    }
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

describe('CDX-010: Over-Broad Command Allow Rules', () => {
  const check = codexChecks.find(c => c.id === 'CDX-010')!;

  function rulesFs(content: string): FSProvider {
    return makeFs({
      access: vi.fn(async () => true),
      readdir: vi.fn(async () => ['default.rules']),
      readFile: vi.fn(async () => content),
    });
  }

  it('flags a bare curl allow rule', async () => {
    const fs = rulesFs('prefix_rule(pattern=["curl"], decision="allow")\n');
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0]?.detail).toContain('curl');
  });

  it('flags an unconstrained shell -lc rule and a flags-only interpreter rule', async () => {
    const fs = rulesFs([
      'prefix_rule(pattern=["/bin/bash", "-lc"], decision="allow")',
      'prefix_rule(pattern=["perl", "-0pi"], decision="allow")',
    ].join('\n'));
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
    expect(result.evidence).toHaveLength(2);
  });

  it('passes scoped prefixes and ignores deny rules', async () => {
    const fs = rulesFs([
      'prefix_rule(pattern=["npm", "run", "build"], decision="allow")',
      'prefix_rule(pattern=["git", "status"], decision="allow")',
      'prefix_rule(pattern=["curl"], decision="deny")',
      'prefix_rule(pattern=["/bin/bash", "-lc", "rg -n pattern src/"], decision="allow")',
    ].join('\n'));
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });

  it('passes when rules directory is absent', async () => {
    const fs = makeFs({ access: vi.fn(async () => false) });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});

describe('CDX-010 rule parsing', () => {
  it('reads every prefix_rule form Codex accepts', async () => {
    const { parsePrefixRules } = await import('./cdx-010-broad-prefix-rules.js');
    const rules = parsePrefixRules([
      'prefix_rule(decision = "allow", pattern = ["curl"])',
      "prefix_rule(pattern = ['bash', '-c'])",
      'prefix_rule(',
      '    pattern = [["python3", "node"], "-e",],',
      '    justification = "scripts (ok)",',
      ')',
      'prefix_rule(pattern = ["rm"], decision = "forbidden")',
      'prefix_rule(pattern = ["git", ["status", "diff"]], decision = "allow")',
    ].join('\n'));
    expect(rules.map(r => [r.line, r.decision, r.patterns])).toEqual([
      [1, 'allow', [['curl']]],
      [2, 'allow', [['bash', '-c']]],
      [3, 'allow', [['python3', '-e'], ['node', '-e']]],
      [7, 'forbidden', [['rm']]],
      [8, 'allow', [['git', 'status'], ['git', 'diff']]],
    ]);
  });
});

describe('deep-test 2026-10-15 regressions (Codex)', () => {
  const byId = (id: string) => codexChecks.find(c => c.id === id)!;
  const root = (data: Record<string, unknown>) => makeConfig('/home/test/.codex/config.toml', data);
  const profileFile = (name: string, data: Record<string, unknown>) => makeConfig(`/home/test/.codex/${name}.config.toml`, data);

  it('CDX-008 reads 0.134+ profile files ($CODEX_HOME/<name>.config.toml); CDX-001/002 leave them to it', async () => {
    const configs = [root({ approval_policy: 'on-request' }), profileFile('yolo', { approval_policy: 'never', sandbox_mode: 'danger-full-access' })];
    const r8 = await byId('CDX-008').run(makeCtx(configs));
    expect(r8.passed).toBe(false);
    expect(r8.evidence).toHaveLength(2);
    expect(r8.evidence?.[0].file).toBe('/home/test/.codex/yolo.config.toml');
    expect((await byId('CDX-001').run(makeCtx(configs))).passed).toBe(true);
    expect((await byId('CDX-002').run(makeCtx(configs))).passed).toBe(true);
  });

  it('CDX-009 inspects notify in profile files but not in project config (ignored there)', async () => {
    const configs = [root({}), profileFile('ci', { notify: ['sh', '-c', 'echo $X'] })];
    expect((await byId('CDX-009').run(makeCtx(configs))).passed).toBe(false);
    const ctx = makeCtx([makeConfig('/repo/.codex/config.toml', { notify: ['sh', '-c', 'x'] })]);
    ctx.installation = { ...ctx.installation, installDir: '/repo/.codex', profile: 'project' };
    expect((await byId('CDX-009').run(ctx)).passed).toBe(true);
  });

  it('CDX-002 flags workspace-write with writable_roots "/" (critical) and network_access (warning)', async () => {
    const wide = await byId('CDX-002').run(makeCtx([root({ sandbox_mode: 'workspace-write', sandbox_workspace_write: { writable_roots: ['/'] } })]));
    expect(wide.passed).toBe(false);
    expect(wide.severity).toBe('critical');
    const net = await byId('CDX-002').run(makeCtx([root({ sandbox_mode: 'workspace-write', sandbox_workspace_write: { network_access: true, writable_roots: ['/home/test/src/app', '/tmp/build'] } })]));
    expect(net.passed).toBe(false);
    expect(net.severity).toBe('warning');
    expect(net.evidence).toHaveLength(1);
    const ok = await byId('CDX-002').run(makeCtx([root({ sandbox_mode: 'read-only', sandbox_workspace_write: { writable_roots: ['~'] } })]));
    expect(ok.passed).toBe(true);
  });

  it('CDX-001 fix text no longer recommends deprecated policies', async () => {
    const r = await byId('CDX-001').run(makeCtx([root({ approval_policy: 'never' })]));
    expect(r.fixDescription).toContain('on-request');
    expect(r.fixDescription).not.toMatch(/untrusted|on-failure/);
  });

  it('CDX-007 scans AGENTS.override.md, and a trusted project root\'s AGENTS.md', async () => {
    const seen: string[] = [];
    const fs = makeFs({
      access: vi.fn(async (p: string) => { seen.push(p); return p.endsWith('AGENTS.override.md'); }),
      readFile: vi.fn(async () => `token ghp_${'a1B2'.repeat(9)}\n`),
    });
    const r = await byId('CDX-007').run(makeCtx([], fs));
    expect(r.passed).toBe(false);
    expect(r.evidence?.[0].file).toBe('/home/test/.codex/AGENTS.override.md');

    const ctx = makeCtx([], makeFs({ access: vi.fn(async (p: string) => { seen.push(p); return false; }) }));
    ctx.installation = { ...ctx.installation, installDir: '/repo/.codex', profile: 'project' };
    await byId('CDX-007').run(ctx);
    expect(seen).toContain('/repo/AGENTS.md');
  });
});

describe('CDX-003 fix', () => {
  it('removes group/other access from auth.json', async () => {
    const { mkdtempSync, writeFileSync, statSync, chmodSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = mkdtempSync(join(tmpdir(), 'vaso-cdx003-'));
    writeFileSync(join(dir, 'auth.json'), '{}');
    chmodSync(join(dir, 'auth.json'), 0o644);
    const check = codexChecks.find(c => c.id === 'CDX-003')!;
    const ctx = makeCtx([]);
    ctx.installation = { ...ctx.installation, installDir: dir };
    expect((await check.run({ ...ctx, fs: makeFs({ stat: vi.fn(async (p: string) => (p.endsWith('auth.json') ? { mode: 0o100644, isFile: () => true, isDirectory: () => false } : { mode: 0o40755, isFile: () => false, isDirectory: () => true })) }) })).fixable).toBe(true);
    const r = await check.fix!(ctx);
    expect(r.applied).toBe(true);
    expect(statSync(join(dir, 'auth.json')).mode & 0o777).toBe(0o600);
  });
});
