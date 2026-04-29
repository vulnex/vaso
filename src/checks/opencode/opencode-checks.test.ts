import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { opencodeChecks } from './index.js';

function makeConfig(filePath: string, data: Record<string, unknown>): ParsedConfig {
  return {
    raw: '',
    format: 'json',
    filePath,
    data,
  };
}

function makeFs(overrides: Partial<FSProvider> = {}): FSProvider {
  return {
    access: vi.fn(async () => false),
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
    agent: 'opencode',
    installDir: '/home/test/.config/opencode',
    configFiles: configs,
  };
  return { installation, configs, platform: 'linux', fs: fs ?? makeFs() };
}

describe('OpenCode checks', () => {
  it('exports 12 checks', () => {
    expect(opencodeChecks).toHaveLength(12);
  });

  it('all checks have coding-agent category and supportedAgents', () => {
    for (const check of opencodeChecks) {
      expect(check.category).toBe('coding-agent');
      expect(check.supportedAgents).toContain('opencode');
    }
  });

  it('all check IDs start with OPC-', () => {
    for (const check of opencodeChecks) {
      expect(check.id).toMatch(/^OPC-0\d{2}$/);
    }
  });
});

describe('OPC-001: Auth file permissions', () => {
  const check = opencodeChecks.find(c => c.id === 'OPC-001')!;

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
    const result = await check.run(makeCtx([], makeFs()));
    expect(result.passed).toBe(true);
  });
});

describe('OPC-002: Permissive permissions', () => {
  const check = opencodeChecks.find(c => c.id === 'OPC-002')!;

  it('fails when top-level permission = "allow"', async () => {
    const config = makeConfig('opencode.json', { permission: 'allow' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('fails when permission.bash = "allow"', async () => {
    const config = makeConfig('opencode.json', { permission: { bash: 'allow' } });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('fails when permission.edit = { "*": "allow" }', async () => {
    const config = makeConfig('opencode.json', { permission: { edit: { '*': 'allow' } } });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when permission.bash = "ask"', async () => {
    const config = makeConfig('opencode.json', { permission: { bash: 'ask', edit: 'ask' } });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('OPC-003: MCP server pinning & transport', () => {
  const check = opencodeChecks.find(c => c.id === 'OPC-003')!;

  it('fails on local MCP using bare bin name', async () => {
    const config = makeConfig('opencode.json', {
      mcp: { fs: { type: 'local', command: ['my-mcp-server'] } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toMatch(/PATH/);
  });

  it('fails on unpinned npx package', async () => {
    const config = makeConfig('opencode.json', {
      mcp: { fs: { type: 'local', command: ['npx', '-y', '@modelcontextprotocol/server-filesystem'] } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toMatch(/version pin/);
  });

  it('passes on pinned npx package', async () => {
    const config = makeConfig('opencode.json', {
      mcp: { fs: { type: 'local', command: ['npx', '-y', '@modelcontextprotocol/server-filesystem@1.2.3'] } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes on absolute local path', async () => {
    const config = makeConfig('opencode.json', {
      mcp: { fs: { type: 'local', command: ['/usr/local/bin/mcp-server'] } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('fails on remote MCP using http://', async () => {
    const config = makeConfig('opencode.json', {
      mcp: { gh: { type: 'remote', url: 'http://example.com/mcp' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toMatch(/plaintext HTTP/);
  });

  it('passes on remote MCP using https://', async () => {
    const config = makeConfig('opencode.json', {
      mcp: { gh: { type: 'remote', url: 'https://example.com/mcp' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('OPC-004: Auto-share', () => {
  const check = opencodeChecks.find(c => c.id === 'OPC-004')!;

  it('fails when share = "auto"', async () => {
    const config = makeConfig('opencode.json', { share: 'auto' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('fails when autoshare = true', async () => {
    const config = makeConfig('opencode.json', { autoshare: true });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('fails when OPENCODE_AUTO_SHARE=1', async () => {
    const fs = makeFs({ getEnv: vi.fn((k: string) => k === 'OPENCODE_AUTO_SHARE' ? '1' : undefined) });
    const result = await check.run(makeCtx([makeConfig('opencode.json', { share: 'manual' })], fs));
    expect(result.passed).toBe(false);
  });

  it('passes when share = "manual"', async () => {
    const config = makeConfig('opencode.json', { share: 'manual' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('OPC-005: Unsafe plugin source', () => {
  const check = opencodeChecks.find(c => c.id === 'OPC-005')!;

  it('fails on http:// plugin URL', async () => {
    const config = makeConfig('opencode.json', { plugin: ['http://evil.example.com/plugin.js'] });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('fails on http:// plugin URL with options tuple', async () => {
    const config = makeConfig('opencode.json', { plugin: [['http://example.com/p.js', { opt: true }]] });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes on https:// URL', async () => {
    const config = makeConfig('opencode.json', { plugin: ['https://example.com/plugin.js'] });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes on npm package name', async () => {
    const config = makeConfig('opencode.json', { plugin: ['opencode-myplugin'] });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('OPC-006: Sub-agent permission downgrade', () => {
  const check = opencodeChecks.find(c => c.id === 'OPC-006')!;

  it('fails when sub-agent upgrades bash from deny to allow', async () => {
    const config = makeConfig('opencode.json', {
      permission: { bash: 'deny' },
      agent: { yolo: { permission: { bash: 'allow' } } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('fails when sub-agent upgrades bash from ask to allow', async () => {
    const config = makeConfig('opencode.json', {
      permission: { bash: 'ask' },
      agent: { yolo: { permission: { bash: 'allow' } } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when sub-agent matches or tightens permissions', async () => {
    const config = makeConfig('opencode.json', {
      permission: { bash: 'ask' },
      agent: { plan: { permission: { bash: 'deny' } } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes when no sub-agent overrides exist', async () => {
    const config = makeConfig('opencode.json', {
      permission: { bash: 'ask' },
      agent: { plan: { model: 'anthropic/claude-opus' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('OPC-007: Memory file secret leak', () => {
  const check = opencodeChecks.find(c => c.id === 'OPC-007')!;

  it('passes when no memory files exist', async () => {
    const result = await check.run(makeCtx([], makeFs()));
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

  it('passes for ordinary memory content', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      readFile: vi.fn(async () => '# Project Memory\nUse npm run build\n'),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});

describe('OPC-008: Continue loop on deny', () => {
  const check = opencodeChecks.find(c => c.id === 'OPC-008')!;

  it('fails when experimental.continue_loop_on_deny = true', async () => {
    const config = makeConfig('opencode.json', { experimental: { continue_loop_on_deny: true } });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when flag is not set', async () => {
    const config = makeConfig('opencode.json', { model: 'anthropic/claude-opus' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('OPC-009: Enterprise URL plaintext', () => {
  const check = opencodeChecks.find(c => c.id === 'OPC-009')!;

  it('fails on http:// enterprise URL', async () => {
    const config = makeConfig('opencode.json', { enterprise: { url: 'http://internal.example.com' } });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes on https:// enterprise URL', async () => {
    const config = makeConfig('opencode.json', { enterprise: { url: 'https://internal.example.com' } });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes when enterprise unset', async () => {
    const result = await check.run(makeCtx([makeConfig('opencode.json', {})]));
    expect(result.passed).toBe(true);
  });
});

describe('OPC-010: Project-relative plugin path', () => {
  const check = opencodeChecks.find(c => c.id === 'OPC-010')!;

  it('fails on ./relative plugin path', async () => {
    const config = makeConfig('opencode.json', { plugin: ['./plugin.ts'] });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('fails on ../parent plugin path', async () => {
    const config = makeConfig('opencode.json', { plugin: ['../shared/plugin.ts'] });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes on absolute file:// URL', async () => {
    const config = makeConfig('opencode.json', { plugin: ['file:///opt/plugins/x.ts'] });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes on npm package name', async () => {
    const config = makeConfig('opencode.json', { plugin: ['opencode-mything'] });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('OPC-011: Snapshot disabled', () => {
  const check = opencodeChecks.find(c => c.id === 'OPC-011')!;

  it('fails when snapshot = false', async () => {
    const config = makeConfig('opencode.json', { snapshot: false });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('info');
  });

  it('passes when snapshot is unset', async () => {
    const result = await check.run(makeCtx([makeConfig('opencode.json', {})]));
    expect(result.passed).toBe(true);
  });
});

describe('OPC-012: Auto-update disabled', () => {
  const check = opencodeChecks.find(c => c.id === 'OPC-012')!;

  it('fails when autoupdate = false', async () => {
    const config = makeConfig('opencode.json', { autoupdate: false });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes when autoupdate = "notify"', async () => {
    const config = makeConfig('opencode.json', { autoupdate: 'notify' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes when autoupdate is unset', async () => {
    const result = await check.run(makeCtx([makeConfig('opencode.json', {})]));
    expect(result.passed).toBe(true);
  });
});
