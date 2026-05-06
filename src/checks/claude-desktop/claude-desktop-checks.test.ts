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

  it('fails on extension manifest with no signature', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      readdirEntries: vi.fn(async () => [
        { name: 'evil-ext', isFile: false, isDirectory: true },
      ]),
      readFile: vi.fn(async () => JSON.stringify({ name: 'evil-ext', version: '1.0.0' })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
  });

  it('passes when manifest has a signature', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      readdirEntries: vi.fn(async () => [
        { name: 'good-ext', isFile: false, isDirectory: true },
      ]),
      readFile: vi.fn(async () => JSON.stringify({ name: 'good-ext', signature: 'abc' })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});

describe('CD-006: Always-Approve MCP Tools', () => {
  const check = claudeDesktopChecks.find(c => c.id === 'CD-006')!;

  it('fails on top-level alwaysApprove array', async () => {
    const config = makeConfig('config.json', {
      alwaysApprove: ['shell', 'fs.write', 'http.fetch'],
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('fails on per-server autoApprove=true', async () => {
    const config = makeConfig('config.json', {
      mcpServers: { fs: { command: 'fs', autoApprove: true } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
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
