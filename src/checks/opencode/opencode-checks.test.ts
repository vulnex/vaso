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

  it('follows $XDG_DATA_HOME for the scanning user', async () => {
    const env: Record<string, string> = { XDG_CONFIG_HOME: '/x/cfg', XDG_DATA_HOME: '/x/data' };
    const fs = makeFs({
      getEnv: vi.fn((k: string) => env[k]),
      access: vi.fn(async (p: string) => p === '/x/data/opencode/auth.json'),
      stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    });
    const ctx = makeCtx([], fs);
    ctx.installation = { ...ctx.installation, installDir: '/x/cfg/opencode' };
    const result = await check.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].file).toBe('/x/data/opencode/auth.json');
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

  // OpenCode defaults bash/edit/task/webfetch to "allow" (opencode.ai/docs/permissions):
  // set explicitly or left at the default, the effective state is the same — info
  it('reports allow-by-default tools as info, whether set explicitly or not', async () => {
    for (const permission of [{ bash: 'allow' }, { edit: { '*': 'allow' } }, undefined]) {
      const result = await check.run(makeCtx([makeConfig('opencode.json', permission ? { permission } : {})]));
      expect(result.passed).toBe(false);
      expect(result.severity).toBe('info');
    }
  });

  it('passes when every allow-by-default tool asks', async () => {
    const config = makeConfig('opencode.json', { permission: { bash: 'ask', edit: 'ask', task: 'ask', webfetch: 'deny' } });
    expect((await check.run(makeCtx([config]))).passed).toBe(true);
    expect((await check.run(makeCtx([makeConfig('opencode.json', { permission: 'ask' })]))).passed).toBe(true);
  });

  it('is critical for loosening what OpenCode asks about by default, and for dangerous scoped bash allows', async () => {
    const ask = { bash: 'ask', edit: 'ask', task: 'ask', webfetch: 'ask' };
    const run = (permission: Record<string, unknown>) => check.run(makeCtx([makeConfig('opencode.json', { permission: { ...ask, ...permission } })]));
    expect((await run({ external_directory: 'allow' })).severity).toBe('critical');
    expect((await run({ external_directory: { '~/**': 'allow' } })).severity).toBe('critical');
    expect((await run({ bash: { '*': 'ask', 'curl *': 'allow' } })).severity).toBe('critical');
    // scoped as documented: a project path, a harmless command
    expect((await run({ external_directory: { '~/projects/shared/*': 'allow' } })).passed).toBe(true);
    expect((await run({ bash: { '*': 'ask', 'git status*': 'allow' } })).passed).toBe(true);
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

  // OpenCode's CLAUDE.md fallback is ~/.claude/CLAUDE.md, never one in its
  // config dir (deep test 2026-11-09)
  it('does not read ~/.config/opencode/CLAUDE.md', async () => {
    const access = vi.fn(async () => true);
    const readFile = vi.fn(async () => '# notes\n');
    await check.run(makeCtx([], makeFs({ access, readFile })));
    expect(readFile.mock.calls.map(c => String(c[0]))).not.toContainEqual(expect.stringMatching(/CLAUDE\.md$/));
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

describe('deep-test 2026-10-15 regressions (OpenCode)', () => {
  const byId = (id: string) => opencodeChecks.find(c => c.id === id)!;

  it('OPC-002 flags the documented global form {"*": "allow"} unless every high-risk key is overridden', async () => {
    const check = byId('OPC-002');
    expect((await check.run(makeCtx([makeConfig('opencode.json', { permission: { '*': 'allow' } })]))).passed).toBe(false);
    expect((await check.run(makeCtx([makeConfig('opencode.json', { permission: { '*': 'allow', webfetch: 'ask' } })]))).passed).toBe(false);
    const covered = { '*': 'allow', bash: 'ask', edit: 'ask', task: 'ask', webfetch: 'ask', external_directory: 'ask' };
    expect((await check.run(makeCtx([makeConfig('opencode.json', { permission: covered })]))).passed).toBe(true);
    expect((await check.run(makeCtx([makeConfig('opencode.json', { permission: { '*': 'ask', bash: { 'git *': 'allow', '*': 'deny' } } })]))).passed).toBe(true);
  });

  it('OPC-006 reads permission from markdown agent frontmatter (agent/ and agents/, $OPENCODE_CONFIG_DIR)', async () => {
    const fs = makeFs({
      readdir: vi.fn(async (p: string) => {
        if (p === '/home/test/.config/opencode/agent') return ['yolo.md', 'notes.txt'];
        if (p === '/srv/oc/agents') return ['review.md'];
        throw new Error('ENOENT');
      }),
      readFile: vi.fn(async (p: string) => p.endsWith('yolo.md')
        ? '---\ndescription: yolo\nmode: subagent\npermission:\n  bash: allow\n  edit: allow\n---\nDo things.\n'
        : '---\npermission:\n  edit: deny\n---\nReview.\n'),
      getEnv: vi.fn((k: string) => (k === 'OPENCODE_CONFIG_DIR' ? '/srv/oc' : undefined)),
    });
    const configs = [makeConfig('opencode.json', { permission: { bash: 'ask', edit: 'ask' } })];
    const result = await byId('OPC-006').run(makeCtx(configs, fs));
    expect(result.passed).toBe(false);
    expect(result.evidence).toHaveLength(2);
    expect(result.evidence?.every(e => e.file === '/home/test/.config/opencode/agent/yolo.md')).toBe(true);
  });
});

describe('OPC-001 fix', () => {
  it('removes group/other access from auth.json in the XDG data dir', async () => {
    const { mkdtempSync, mkdirSync, writeFileSync, statSync, chmodSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const home = mkdtempSync(join(tmpdir(), 'vaso-opc001-'));
    const data = join(home, '.local', 'share', 'opencode');
    mkdirSync(data, { recursive: true });
    writeFileSync(join(data, 'auth.json'), '{}');
    chmodSync(join(data, 'auth.json'), 0o640);
    const ctx = makeCtx([], makeFs({ homedir: () => home }));
    ctx.installation = { ...ctx.installation, installDir: join(home, '.config', 'opencode') };
    const r = await opencodeChecks.find(c => c.id === 'OPC-001')!.fix!(ctx);
    expect(r.applied).toBe(true);
    expect(statSync(join(data, 'auth.json')).mode & 0o777).toBe(0o600);
  });
});
