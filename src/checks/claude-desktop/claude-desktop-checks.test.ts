import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { claudeDesktopChecks } from './index.js';

function makeConfig(filePath: string, data: Record<string, unknown>): ParsedConfig {
  return {
    raw: JSON.stringify(data, null, 2),
    format: 'json',
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
    platform: 'darwin',
    ...overrides,
  } as FSProvider;
}

function makeCtx(configs: ParsedConfig[], fs?: FSProvider): ScanContext {
  const installation: AgentInstallation = {
    agent: 'claude-desktop',
    installDir: '/home/test/Library/Application Support/Claude',
    configFiles: configs,
  };
  return { installation, configs, platform: 'darwin', fs: fs ?? makeFs() };
}

describe('Claude Desktop checks', () => {
  it('exports 10 checks', () => {
    expect(claudeDesktopChecks).toHaveLength(10);
  });

  it('all checks have coding-agent category and supportedAgents', () => {
    for (const check of claudeDesktopChecks) {
      expect(check.category).toBe('coding-agent');
      expect(check.supportedAgents).toContain('claude-desktop');
    }
  });

  it('all check IDs start with CD-', () => {
    for (const check of claudeDesktopChecks) {
      expect(check.id).toMatch(/^CD-0\d{2}$/);
    }
  });
});

describe('CD-001: Plaintext API Key in Desktop Config', () => {
  const check = claudeDesktopChecks.find(c => c.id === 'CD-001')!;

  it('fails on plaintext API key in mcpServers env', async () => {
    const config = makeConfig('config.json', {
      mcpServers: {
        github: {
          command: 'npx',
          env: { GITHUB_TOKEN: 'ghp_abcdefghijklmnopqrstuvwxyz0123456789' },
        },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when env values are env-var references', async () => {
    const config = makeConfig('config.json', {
      mcpServers: {
        github: {
          command: 'npx',
          env: { GITHUB_TOKEN: '$GITHUB_TOKEN' },
        },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CD-002: Desktop Config File Permissions', () => {
  const check = claudeDesktopChecks.find(c => c.id === 'CD-002')!;

  it('fails when config holds env values and is world-readable', async () => {
    const config = makeConfig('/path/config.json', {
      mcpServers: { github: { env: { GITHUB_TOKEN: 'ghp_x' } } },
    });
    const fs = makeFs({
      stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([config], fs));
    expect(result.passed).toBe(false);
  });

  it('passes when config has no env values, even if mode is loose', async () => {
    const config = makeConfig('/path/config.json', {
      globalShortcut: 'Cmd+Shift+Space',
    });
    const fs = makeFs({
      stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([config], fs));
    expect(result.passed).toBe(true);
  });
});

describe('CD-003: Unpinned MCP Server Package', () => {
  const check = claudeDesktopChecks.find(c => c.id === 'CD-003')!;

  it('fails on unpinned npx package', async () => {
    const config = makeConfig('config.json', {
      mcpServers: {
        fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes on version-pinned npx package', async () => {
    const config = makeConfig('config.json', {
      mcpServers: {
        fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.2.3'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CD-004: Cleartext HTTP MCP Server', () => {
  const check = claudeDesktopChecks.find(c => c.id === 'CD-004')!;

  it('fails on http:// remote URL', async () => {
    const config = makeConfig('config.json', {
      mcpServers: { remote: { url: 'http://api.example.com/mcp' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes on https://', async () => {
    const config = makeConfig('config.json', {
      mcpServers: { remote: { url: 'https://api.example.com/mcp' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('tolerates http://localhost', async () => {
    const config = makeConfig('config.json', {
      mcpServers: { local: { url: 'http://localhost:8080/mcp' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CD-005: Unverified MCPB Desktop Extensions', () => {
  const check = claudeDesktopChecks.find(c => c.id === 'CD-005')!;

  it('passes when no Extensions directory present', async () => {
    const fs = makeFs({
      access: vi.fn(async () => false),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });

  function extFs(archive?: { name: string; bytes: Uint8Array }) {
    return makeFs({
      access: vi.fn(async () => true),
      readdirEntries: vi.fn(async (dir: string) => dir.endsWith('Claude Extensions')
        ? [{ name: 'ext', isFile: false, isDirectory: true }]
        : archive ? [{ name: archive.name, isFile: true, isDirectory: false }] : []),
      readFile: vi.fn(async () => JSON.stringify({ name: 'ext', version: '1.0.0', author: { name: 'Anthropic' } })),
      readBytes: vi.fn(async () => { if (!archive) throw new Error('ENOENT'); return archive.bytes; }),
    });
  }
  const zip = Buffer.from('PK\u0003\u0004 zip body');

  it('an installed extension without its bundle is inventory only — never "unsigned"', async () => {
    const fs = extFs();
    (fs.access as ReturnType<typeof vi.fn>).mockImplementation(async (p: string) => !p.endsWith('.mcpb'));
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('info');
    expect(result.evidence?.[0].snippet).toBe('extension: ext (author: Anthropic)');
    expect(result.message).toMatch(/signature status unknown/);
  });

  it('flags a .mcpb bundle with no MCPB_SIG_V1 trailer', async () => {
    const result = await check.run(makeCtx([], extFs({ name: 'ext.mcpb', bytes: zip })));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
    expect(result.message).toMatch(/unsigned/);
  });

  const block = (sig: Buffer, length = sig.length) => {
    const len = Buffer.alloc(4);
    len.writeUInt32LE(length);
    return Buffer.concat([zip, Buffer.from('MCPB_SIG_V1'), len, sig, Buffer.from('MCPB_SIG_END')]);
  };

  it('passes a signed bundle', async () => {
    const der = Buffer.from([0x30, 0x82, 0x01, 0x00, ...Buffer.from('pkcs7')]);
    const result = await check.run(makeCtx([], extFs({ name: 'ext.mcpb', bytes: block(der) })));
    expect(result.passed).toBe(true);
  });

  it('a zero-length, mis-sized or non-DER signature block is unsigned', async () => {
    const der = Buffer.from([0x30, 0x82, 0x01, 0x00, ...Buffer.from('pkcs7')]);
    for (const bytes of [block(Buffer.alloc(0)), block(der, der.length + 10), block(Buffer.from('not-der'))]) {
      const result = await check.run(makeCtx([], extFs({ name: 'ext.mcpb', bytes })));
      expect(result.passed).toBe(false);
      expect(result.message).toMatch(/unsigned/);
    }
  });
});

describe('CD-006: Always-Approve MCP Tools', () => {
  const check = claudeDesktopChecks.find(c => c.id === 'CD-006')!;

  it('reports keys Claude Desktop does not read as info', async () => {
    const config = makeConfig('config.json', {
      alwaysApprove: ['shell', 'fs.write', 'http.fetch'],
      mcpServers: { fs: { command: 'fs', autoApprove: true } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('info');
    expect(result.evidence?.every(e => e.mitigated)).toBe(true);
  });

  it('is critical when claude-autoapprove-mcp applies an autoapprove list', async () => {
    const config = makeConfig('config.json', {
      mcpServers: {
        'claude-autoapprove-mcp': { command: 'uvx', args: ['claude-autoapprove-mcp'] },
        shell: { command: 'shell-mcp', autoapprove: ['run_command'] },
        other: { command: 'x', autoApprove: ['a'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence?.filter(e => !e.mitigated).map(e => e.snippet)).toEqual(['mcpServers.shell.autoapprove = ["run_command"]']);
  });

  it('reads every approval spelling on a server: an injector list behind another client\'s key still counts', async () => {
    const config = makeConfig('config.json', {
      mcpServers: {
        'claude-autoapprove-mcp': { command: 'uvx', args: ['claude-autoapprove-mcp'] },
        shell: { command: 'shell-mcp', autoApprove: ['x'], autoapprove: ['run_command'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.severity).toBe('critical');
    expect(result.evidence?.filter(e => !e.mitigated).map(e => e.snippet)).toEqual(['mcpServers.shell.autoapprove = ["run_command"]']);
    expect(result.evidence?.filter(e => e.mitigated).map(e => e.snippet)).toEqual(['mcpServers.shell.autoApprove = ["x"]']);
  });

  it('an injector autoapprove of true or "*" approves nothing (exact tool names only)', async () => {
    const config = makeConfig('config.json', {
      mcpServers: {
        'claude-autoapprove-mcp': { command: 'uvx', args: ['claude-autoapprove-mcp'] },
        a: { command: 'a', autoapprove: true },
        b: { command: 'b', autoapprove: ['*'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.severity).toBe('info');
    expect(result.evidence).toHaveLength(2);
  });

  it('passes when no auto-approve fields set', async () => {
    const config = makeConfig('config.json', {
      mcpServers: { fs: { command: 'fs' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CD-007: Sensitive Filesystem Server Scope', () => {
  const check = claudeDesktopChecks.find(c => c.id === 'CD-007')!;

  it('fails when filesystem server is granted ~/.ssh', async () => {
    const config = makeConfig('config.json', {
      mcpServers: {
        filesystem: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-filesystem', '~/.ssh'],
        },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('uses ctx.fs.homedir() (not the scanner host) to resolve sensitive paths', async () => {
    const remoteHome = '/snap/remote-user';
    const config = makeConfig('config.json', {
      mcpServers: {
        filesystem: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-filesystem', `${remoteHome}/.ssh`],
        },
      },
    });
    const fs = makeFs({ homedir: () => remoteHome });
    const result = await check.run(makeCtx([config], fs));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when filesystem server scope is a dedicated working directory', async () => {
    const config = makeConfig('config.json', {
      mcpServers: {
        filesystem: {
          command: 'npx',
          args: ['-y', '@modelcontextprotocol/server-filesystem', '/Users/me/projects/work'],
        },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes a folder inside the home directory, fails the home dir and its parents', async () => {
    const home = '/Users/me';
    const fs = makeFs({ homedir: () => home });
    const fsServer = (path: string) => makeConfig('config.json', {
      mcpServers: { filesystem: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', path] } },
    });
    for (const ok of ['~/Documents/work', `${home}/projects`, '~/.sshkeys-notes']) {
      expect((await check.run(makeCtx([fsServer(ok)], fs))).passed, ok).toBe(true);
    }
    for (const bad of ['~', `${home}/`, '/Users', '/', '~/.ssh/keys', '~/.aws']) {
      expect((await check.run(makeCtx([fsServer(bad)], fs))).passed, bad).toBe(false);
    }
  });

  it('only inspects filesystem-server entries (skips others)', async () => {
    const config = makeConfig('config.json', {
      mcpServers: {
        github: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-github', '/etc'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CD-008: Stdio MCP via Shell -c', () => {
  const check = claudeDesktopChecks.find(c => c.id === 'CD-008')!;

  it('fails on bash -c invocation', async () => {
    const config = makeConfig('config.json', {
      mcpServers: { evil: { command: '/bin/bash', args: ['-c', 'mcp-server --foo'] } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes on direct binary invocation', async () => {
    const config = makeConfig('config.json', {
      mcpServers: { ok: { command: '/usr/local/bin/mcp-server', args: ['--foo'] } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CD-009: World-Writable MCP Command Path', () => {
  const check = claudeDesktopChecks.find(c => c.id === 'CD-009')!;

  it('fails when command binary is world-writable', async () => {
    const config = makeConfig('config.json', {
      mcpServers: { x: { command: '/tmp/mcp' } },
    });
    const fs = makeFs({
      stat: vi.fn(async () => ({ mode: 0o777, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([config], fs));
    expect(result.passed).toBe(false);
  });

  it('passes when command and parent are not world-writable', async () => {
    const config = makeConfig('config.json', {
      mcpServers: { x: { command: '/usr/local/bin/mcp' } },
    });
    const fs = makeFs({
      stat: vi.fn(async () => ({ mode: 0o755, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([config], fs));
    expect(result.passed).toBe(true);
  });
});

describe('CD-010: Credentials Embedded in MCP URL/Headers', () => {
  const check = claudeDesktopChecks.find(c => c.id === 'CD-010')!;

  it('fails on basic-auth in URL', async () => {
    const config = makeConfig('config.json', {
      mcpServers: { x: { url: 'https://user:pass@api.example.com/mcp' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('fails on api_key query parameter', async () => {
    const config = makeConfig('config.json', {
      mcpServers: { x: { url: 'https://api.example.com/mcp?api_key=secret123abc' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('fails on static Bearer token in headers', async () => {
    const config = makeConfig('config.json', {
      mcpServers: {
        x: {
          url: 'https://api.example.com/mcp',
          headers: { Authorization: 'Bearer abcdef0123456789xyz' },
        },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes on plain https url with no embedded credentials', async () => {
    const config = makeConfig('config.json', {
      mcpServers: { x: { url: 'https://api.example.com/mcp' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('CD-002 fix', () => {
  it('removes group/other access from a config holding MCP env values, and leaves others alone', async () => {
    const { mkdtempSync, writeFileSync, statSync, chmodSync } = await import('node:fs');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = mkdtempSync(join(tmpdir(), 'vaso-cd002-'));
    const withEnv = join(dir, 'claude_desktop_config.json');
    const bare = join(dir, 'other.json');
    for (const f of [withEnv, bare]) { writeFileSync(f, '{}'); chmodSync(f, 0o644); }
    const configs = [
      makeConfig(withEnv, { mcpServers: { a: { command: 'x', env: { K: 'v' } } } }),
      makeConfig(bare, { globalShortcut: 'x' }),
    ];
    const check = claudeDesktopChecks.find(c => c.id === 'CD-002')!;
    const r = await check.fix!(makeCtx(configs));
    expect(r.applied).toBe(true);
    expect(statSync(withEnv).mode & 0o777).toBe(0o600);
    expect(statSync(bare).mode & 0o777).toBe(0o644);
  });
});
