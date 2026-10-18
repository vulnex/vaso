import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { windsurfChecks } from './index.js';

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

function makeCtx(configs: ParsedConfig[], fs?: FSProvider, platform: NodeJS.Platform = 'linux'): ScanContext {
  const installation: AgentInstallation = {
    agent: 'windsurf',
    installDir: '/home/test/.codeium/windsurf',
    configFiles: configs,
  };
  return { installation, configs, platform, fs: fs ?? makeFs() };
}

describe('Windsurf checks', () => {
  it('exports 9 checks', () => {
    expect(windsurfChecks).toHaveLength(9);
  });

  it('all checks have coding-agent category and supportedAgents', () => {
    for (const check of windsurfChecks) {
      expect(check.category).toBe('coding-agent');
      expect(check.supportedAgents).toContain('windsurf');
    }
  });

  it('all check IDs start with WS-', () => {
    for (const check of windsurfChecks) {
      expect(check.id).toMatch(/^WS-0\d{2}$/);
    }
  });

  it('all check names are prefixed with Windsurf', () => {
    for (const check of windsurfChecks) {
      expect(check.name).toMatch(/^Windsurf /);
    }
  });
});

describe('WS-001: Windsurf Auto-Execution Policy', () => {
  const check = windsurfChecks.find(c => c.id === 'WS-001')!;

  it('fails critical when autoExecutionPolicy = "turbo"', async () => {
    const config = makeConfig('settings.json', { 'windsurf.autoExecutionPolicy': 'turbo' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('fails warning when autoExecutionPolicy = "auto"', async () => {
    const config = makeConfig('settings.json', { 'windsurf.autoExecutionPolicy': 'auto' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
  });

  it('matches case-insensitively', async () => {
    const config = makeConfig('settings.json', { 'windsurf.autoExecutionPolicy': 'Turbo' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('passes when autoExecutionPolicy = "off"', async () => {
    const config = makeConfig('settings.json', { 'windsurf.autoExecutionPolicy': 'off' });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes when the setting is absent', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {})]));
    expect(result.passed).toBe(true);
  });
});

describe('WS-002: Windsurf Over-Broad Command Allowlist', () => {
  const check = windsurfChecks.find(c => c.id === 'WS-002')!;

  it('flags a bare dangerous command entry', async () => {
    const config = makeConfig('settings.json', {
      'windsurf.cascadeCommandsAllowList': ['bash'],
      'windsurf.cascadeCommandsDenyList': ['rm *'],
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].snippet).toContain('bash');
  });

  it('flags a dangerous prefix pattern like "curl *"', async () => {
    const config = makeConfig('settings.json', {
      'windsurf.cascadeCommandsAllowList': ['curl *'],
      'windsurf.cascadeCommandsDenyList': ['rm *'],
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('flags a non-trivial allowlist with no deny list as a single evidence item', async () => {
    const config = makeConfig('settings.json', {
      'windsurf.cascadeCommandsAllowList': ['git status', 'npm run build', 'ls -la'],
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.evidence).toHaveLength(1);
    expect(result.evidence?.[0].detail).toContain('no deny list');
  });

  it('passes for narrow entries with a deny list', async () => {
    const config = makeConfig('settings.json', {
      'windsurf.cascadeCommandsAllowList': ['git status', 'npm run build', 'ls -la'],
      'windsurf.cascadeCommandsDenyList': ['rm *', 'sudo *'],
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('does not flag narrowed prefix grants ("python3 scripts/build.py *")', async () => {
    const config = makeConfig('settings.json', {
      'windsurf.cascadeCommandsAllowList': ['python3 scripts/build.py *'],
      'windsurf.cascadeCommandsDenyList': ['rm *'],
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes when the allowlist is absent', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {})]));
    expect(result.passed).toBe(true);
  });
});

describe('WS-003: Windsurf Plaintext Secrets in MCP Config', () => {
  const check = windsurfChecks.find(c => c.id === 'WS-003')!;

  it('flags a literal secret under a secret-named env key', async () => {
    const config = makeConfig('mcp_config.json', {
      mcpServers: {
        github: { command: 'npx', env: { GITHUB_TOKEN: 'ghp_' + 'a1B2c3D4'.repeat(4) } },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('flags a literal Authorization header value', async () => {
    const config = makeConfig('mcp_config.json', {
      mcpServers: {
        remote: { serverUrl: 'https://mcp.example.com', headers: { Authorization: 'Bearer sk-live-abc123' } },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].snippet).toContain('headers.Authorization');
  });

  it('passes for ${env:} and ${file:} interpolated values', async () => {
    const config = makeConfig('mcp_config.json', {
      mcpServers: {
        github: {
          command: 'npx',
          env: { GITHUB_TOKEN: '${env:GITHUB_TOKEN}' },
          headers: { Authorization: '${file:/home/test/.secrets/token}' },
        },
        remote: {
          serverUrl: 'https://mcp.example.com',
          headers: { Authorization: 'Bearer ${env:TOK}', 'X-Api-Key': 'key-${env:A}-${env:B}' },
        },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('flags the literal part of a partly interpolated value', async () => {
    const config = makeConfig('mcp_config.json', {
      mcpServers: { remote: { serverUrl: 'https://x', headers: { Authorization: 'Bearer abcd1234efgh5678 ${env:X}' } } },
    });
    expect((await check.run(makeCtx([config]))).passed).toBe(false);
  });

  it('skips placeholders, booleans and numbers', async () => {
    const config = makeConfig('mcp_config.json', {
      mcpServers: {
        s: {
          command: 'npx',
          env: {
            API_KEY: 'YOUR_API_KEY_HERE',
            AUTH_TOKEN: '<insert-token>',
            USE_TLS: 'false',
            API_TIMEOUT: '30000000',
          },
        },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes when no MCP servers are configured', async () => {
    const result = await check.run(makeCtx([makeConfig('mcp_config.json', {})]));
    expect(result.passed).toBe(true);
  });
});

describe('WS-004: Windsurf Unpinned MCP Package', () => {
  const check = windsurfChecks.find(c => c.id === 'WS-004')!;

  it('fails on npx with no version pin', async () => {
    const config = makeConfig('mcp_config.json', {
      mcpServers: {
        fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('passes on npx with a pinned scoped package', async () => {
    const config = makeConfig('mcp_config.json', {
      mcpServers: {
        fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem@1.2.3'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('fails on pnpm dlx with an unpinned package', async () => {
    const config = makeConfig('mcp_config.json', {
      mcpServers: {
        srv: { command: 'pnpm', args: ['dlx', 'some-mcp-server'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('fails on uvx with an unpinned package', async () => {
    const config = makeConfig('mcp_config.json', {
      mcpServers: {
        srv: { command: 'uvx', args: ['mcp-server-fetch'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('ignores non-runner commands and remote servers', async () => {
    const config = makeConfig('mcp_config.json', {
      mcpServers: {
        local: { command: '/usr/local/bin/my-server', args: ['--stdio'] },
        remote: { serverUrl: 'https://mcp.example.com' },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });
});

describe('WS-005: Windsurf Insecure MCP Server URL', () => {
  const check = windsurfChecks.find(c => c.id === 'WS-005')!;

  it('fails on a non-loopback http:// serverUrl', async () => {
    const config = makeConfig('mcp_config.json', {
      mcpServers: { r: { serverUrl: 'http://mcp.example.com/sse' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
  });

  it('fails on a lookalike loopback host', async () => {
    const config = makeConfig('mcp_config.json', {
      mcpServers: { r: { serverUrl: 'http://localhost.evil.com/sse' } },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
  });

  it('allows http://localhost and http://127.0.0.1', async () => {
    const config = makeConfig('mcp_config.json', {
      mcpServers: {
        a: { serverUrl: 'http://localhost:8080/mcp' },
        b: { serverUrl: 'http://127.0.0.1:3000' },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('passes for https URLs and stdio servers', async () => {
    const config = makeConfig('mcp_config.json', {
      mcpServers: {
        a: { serverUrl: 'https://mcp.example.com' },
        b: { command: 'npx', args: ['-y', 'srv@1.0.0'] },
      },
    });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(true);
  });

  it('reads the `url` key of the Devin-format config too', async () => {
    const config = makeConfig('mcp_config.json', { mcpServers: { r: { url: 'http://mcp.example.com/mcp' } } });
    const result = await check.run(makeCtx([config]));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].snippet).toContain('.url:');
  });
});

describe('WS-006: Windsurf Turbo Directive in Workflows', () => {
  const check = windsurfChecks.find(c => c.id === 'WS-006')!;

  it('flags a // turbo line with file and line number', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      readdir: vi.fn(async () => ['deploy.md', 'notes.txt']),
      readFile: vi.fn(async () => '# Deploy\n\n// turbo\n1. Run `npm run deploy`\n'),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].file).toContain('global_workflows/deploy.md');
    expect(result.evidence?.[0].line).toBe(3);
  });

  it('calls out // turbo-all in the detail', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      readdir: vi.fn(async () => ['release.md']),
      readFile: vi.fn(async () => '// turbo-all\n# Release\n'),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].detail).toContain('turbo-all');
  });

  it('passes when workflow files have no turbo directives', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      readdir: vi.fn(async () => ['build.md']),
      readFile: vi.fn(async () => '# Build\n1. npm ci\n2. npm run build\n'),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });

  it('passes when the workflows directory is absent', async () => {
    const fs = makeFs({ access: vi.fn(async () => false) });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});

describe('WS-007: Windsurf Legacy Plaintext API Key File', () => {
  const check = windsurfChecks.find(c => c.id === 'WS-007')!;

  it('fails when ~/.codeium/config.json is readable by others', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].snippet).toContain('644');
  });

  it('passes when the file is mode 0600', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      stat: vi.fn(async () => ({ mode: 0o600, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });

  it('passes when the file is absent', async () => {
    const fs = makeFs({ access: vi.fn(async () => false) });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });

  it('skips cleanly when permission facts are unsupported (win32 provider)', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      platform: 'win32',
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
    expect(result.message).toContain('skipping');
  });
});

describe('WS-008: Windsurf Editor State DB Readable', () => {
  const check = windsurfChecks.find(c => c.id === 'WS-008')!;

  it('fails when state.vscdb is readable by others (linux path)', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('state.vscdb')),
      stat: vi.fn(async () => ({ mode: 0o644, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].file).toContain('.config/Windsurf/User/globalStorage/state.vscdb');
  });

  it('probes the macOS user-data path on darwin', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('state.vscdb') && p.includes('Application Support/Devin')),
      stat: vi.fn(async () => ({ mode: 0o664, isFile: () => true, isDirectory: () => false })),
      platform: 'darwin',
    });
    const result = await check.run(makeCtx([], fs, 'darwin'));
    expect(result.passed).toBe(false);
    expect(result.evidence?.[0].file).toContain('Library/Application Support/Devin');
  });

  it('passes when state.vscdb is mode 0600', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('state.vscdb')),
      stat: vi.fn(async () => ({ mode: 0o600, isFile: () => true, isDirectory: () => false })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });

  it('passes when no state DB exists', async () => {
    const fs = makeFs({ access: vi.fn(async () => false) });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });

  it('skips on unsupported platforms', async () => {
    const result = await check.run(makeCtx([], makeFs(), 'win32'));
    expect(result.passed).toBe(true);
    expect(result.message).toContain('not applicable');
  });
});

// Devin Desktop 3.x: execution-gate settings come from ~/.codeium/windsurf/user_settings.pb,
// projected by the adapter onto the nested `windsurf` object.
describe('WS-001/WS-002 on Devin Desktop 3.x (user_settings.pb)', () => {
  const ws001 = windsurfChecks.find(c => c.id === 'WS-001')!;
  const ws002 = windsurfChecks.find(c => c.id === 'WS-002')!;
  const pb = (windsurf: Record<string, unknown>) =>
    makeConfig('/home/test/.codeium/windsurf/user_settings.pb', { windsurf });

  it('WS-001 fails critical on a Turbo policy decoded from user_settings.pb', async () => {
    const result = await ws001.run(makeCtx([pb({ autoExecutionPolicy: 'turbo' })]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('critical');
    expect(result.evidence?.[0].file).toContain('user_settings.pb');
  });

  it('WS-001 warns on turbo web-request auto-execution', async () => {
    const result = await ws001.run(makeCtx([pb({ autoExecutionPolicy: 'off', webRequestsAutoExecutionPolicy: 'turbo' })]));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
    expect(result.evidence?.[0].detail).toContain('Web requests');
  });

  it('WS-001 says the product default applies when no policy is set anywhere', async () => {
    const result = await ws001.run(makeCtx([pb({})]));
    expect(result.passed).toBe(true);
    expect(result.message).toContain('product default');
  });

  it('WS-002 flags a bare shell in the decoded allowlist', async () => {
    const result = await ws002.run(makeCtx([pb({ cascadeCommandsAllowList: ['bash'] })]));
    expect(result.passed).toBe(false);
  });

  it('WS-002 reports that no allowlist is configured rather than a clean allowlist', async () => {
    const result = await ws002.run(makeCtx([pb({})]));
    expect(result.passed).toBe(true);
    expect(result.message).toContain('No Cascade command allowlist configured');
  });
});

describe('deep-test 2026-10-15 regressions', () => {
  const byId = (id: string) => windsurfChecks.find(c => c.id === id)!;

  it('WS-005 treats [::1] and 127.0.0.0/8 as loopback, look-alike hosts as remote', async () => {
    const cfg = (serverUrl: string) => makeConfig('/home/test/.codeium/windsurf/mcp_config.json', { mcpServers: { s: { serverUrl } } });
    for (const url of ['http://[::1]:3000/mcp', 'http://127.0.0.5/mcp', 'http://localhost/mcp']) {
      expect((await byId('WS-005').run(makeCtx([cfg(url)]))).passed, url).toBe(true);
    }
    for (const url of ['http://localhost.evil.com/mcp', 'http://127.0.0.1.nip.io/mcp']) {
      expect((await byId('WS-005').run(makeCtx([cfg(url)]))).passed, url).toBe(false);
    }
  });

  it('WS-006 scans workspace .devin/workflows and .windsurf/workflows up to the git root', async () => {
    const cwd = process.cwd();
    const root = cwd.slice(0, cwd.lastIndexOf('/')) || '/';
    const files: Record<string, string[]> = {
      [`${root}/.devin/workflows`]: ['ship.md'],
      [`${cwd}/.windsurf/workflows`]: ['legacy.md'],
    };
    const fs = makeFs({
      access: vi.fn(async (p: string) => p in files || p === `${root}/.git`),
      readdir: vi.fn(async (p: string) => files[p] ?? []),
      readFile: vi.fn(async () => '// turbo\nnpm publish\n'),
    });
    const result = await byId('WS-006').run(makeCtx([], fs));
    expect(result.evidence?.map(e => e.file).sort()).toEqual([
      `${cwd}/.windsurf/workflows/legacy.md`,
      `${root}/.devin/workflows/ship.md`,
    ].sort());
  });
});
