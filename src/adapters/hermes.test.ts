import { describe, it, expect, vi, beforeEach } from 'vitest';
import { join } from 'node:path';
import { hermesAdapter } from './hermes.js';

vi.mock('node:fs/promises', () => ({
  access: vi.fn(),
  readdir: vi.fn(),
  readFile: vi.fn(),
  stat: vi.fn(),
  realpath: vi.fn(),
}));

vi.mock('node:child_process', () => ({
  execFileSync: vi.fn(),
  execFile: vi.fn(),
}));

vi.mock('../core/config-loader.js', () => ({
  loadConfig: vi.fn(),
}));

import { access } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { loadConfig } from '../core/config-loader.js';

const mockAccess = vi.mocked(access);
const mockExecFileSync = vi.mocked(execFileSync);
const mockLoadConfig = vi.mocked(loadConfig);

function setExistingPaths(paths: string[]): void {
  const pathSet = new Set(paths);
  mockAccess.mockImplementation(async (path) => {
    if (pathSet.has(path as string)) return undefined;
    throw new Error('ENOENT');
  });
}

function mockConfig(filePath: string, data: Record<string, unknown> = {}) {
  return {
    raw: JSON.stringify(data),
    format: 'yaml' as const,
    filePath,
    data,
  };
}

describe('Hermes adapter', () => {
  const home = process.env.HOME || '/home/testuser';
  const hermesHome = join(home, '.hermes');

  beforeEach(() => {
    vi.resetAllMocks();
    delete process.env.HERMES_HOME;
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
  });

  it('returns empty array when .hermes dir does not exist', async () => {
    setExistingPaths([]);
    const result = await hermesAdapter.detect();
    expect(result).toEqual([]);
  });

  it('returns empty array when .hermes exists but has no config files', async () => {
    setExistingPaths([hermesHome]);
    mockLoadConfig.mockRejectedValue(new Error('ENOENT'));
    const result = await hermesAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from config.yaml', async () => {
    const configPath = join(hermesHome, 'config.yaml');
    setExistingPaths([hermesHome, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, {
          model: { default: 'anthropic/claude-opus-4.6' },
        });
      }
      throw new Error('ENOENT');
    });

    const result = await hermesAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('hermes');
    expect(result[0].installDir).toBe(hermesHome);
    expect(result[0].configFiles).toHaveLength(1);
  });

  it('detects installation from .env', async () => {
    const envPath = join(hermesHome, '.env');
    setExistingPaths([hermesHome, envPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === envPath) {
        return mockConfig(envPath, { OPENROUTER_API_KEY: 'sk-test' });
      }
      throw new Error('ENOENT');
    });

    const result = await hermesAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('hermes');
  });

  it('loads both config.yaml and .env when present', async () => {
    const configPath = join(hermesHome, 'config.yaml');
    const envPath = join(hermesHome, '.env');
    setExistingPaths([hermesHome, configPath, envPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) return mockConfig(configPath, { model: {} });
      if (path === envPath) return mockConfig(envPath, { OPENROUTER_API_KEY: 'sk-test' });
      throw new Error('ENOENT');
    });

    const result = await hermesAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].configFiles).toHaveLength(2);
  });

  it('extracts version from CLI', async () => {
    const configPath = join(hermesHome, 'config.yaml');
    setExistingPaths([hermesHome, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) return mockConfig(configPath, {});
      throw new Error('ENOENT');
    });
    mockExecFileSync.mockImplementation(((cmd: string) =>
      cmd === 'which' ? '/usr/local/bin/hermes\n' : 'Hermes Agent v0.6.0\n') as any);

    const result = await hermesAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].version).toBe('0.6.0');
  });

  it('reads the version from install-stamp.json without exec, and rejects 0.0.0 from --version', async () => {
    const hh = '/home/u/.hermes';
    const files: Record<string, string> = {
      [`${hh}/hermes-agent/install-stamp.json`]: '{"baseVersion":"0.22.0"}',
      '/home/u/.local/bin/hermes': '',
    };
    const execSync = vi.fn((cmd: string) => (cmd === 'which' ? '/home/u/.local/bin/hermes\n' : 'Hermes Agent v0.0.0\n'));
    const fs = {
      kind: 'local',
      platform: 'linux',
      homedir: () => '/home/u',
      getEnv: () => undefined,
      access: vi.fn(async (p: string) => p === hh || p === `${hh}/config.yaml` || p in files),
      readFile: vi.fn(async (p: string) => {
        if (p in files) return files[p];
        throw new Error('ENOENT');
      }),
      stat: vi.fn(async () => ({ mode: 0o100755, isFile: () => true, isDirectory: () => false })),
      readdirEntries: vi.fn(async () => []),
      realpath: vi.fn(async (p: string) => p),
      execSync,
    } as any;
    mockLoadConfig.mockImplementation(async (path) => mockConfig(path as string, {}));

    let [inst] = await hermesAdapter.detect({ fs });
    expect(inst.version).toBe('0.22.0');
    expect(execSync.mock.calls.some(c => c[0] !== 'which')).toBe(false);

    delete files[`${hh}/hermes-agent/install-stamp.json`];
    [inst] = await hermesAdapter.detect({ fs });
    expect(inst.version).toBeUndefined();
  });

  it('reports no gateway when the installed release refuses to start the API server, and never loads cli-config.yaml', async () => {
    const hh = '/home/u/.hermes';
    const files: Record<string, string> = { [`${hh}/hermes-agent/install-stamp.json`]: '{"baseVersion":"0.21.6"}' };
    const present = new Set([hh, `${hh}/config.yaml`, `${hh}/cli-config.yaml`]);
    const fs = {
      kind: 'local',
      platform: 'linux',
      homedir: () => '/home/u',
      getEnv: () => undefined,
      access: vi.fn(async (p: string) => present.has(p) || p in files),
      readFile: vi.fn(async (p: string) => {
        if (p in files) return files[p];
        throw new Error('ENOENT');
      }),
      stat: vi.fn(async () => ({ mode: 0o100644, isFile: () => true, isDirectory: () => false })),
      readdirEntries: vi.fn(async () => []),
      realpath: vi.fn(async (p: string) => p),
      execSync: vi.fn(() => { throw new Error('not found'); }),
    } as any;
    let api: Record<string, unknown> = { enabled: true, host: '0.0.0.0' };
    mockLoadConfig.mockImplementation(async (path) => mockConfig(path as string, { gateway: { api_server: api } }));

    let [inst] = await hermesAdapter.detect({ fs });
    expect(inst.gateway).toBeUndefined();
    expect(inst.configFiles.map(c => c.filePath)).toEqual([`${hh}/config.yaml`]);

    api = { enabled: true, host: '0.0.0.0', key: 'a3f9c27e5b1d4086f2e7' };
    [inst] = await hermesAdapter.detect({ fs });
    expect(inst.gateway).toEqual({ host: '0.0.0.0', port: 8642 });
  });

  it('respects HERMES_HOME env var', async () => {
    const customHome = '/opt/hermes';
    process.env.HERMES_HOME = customHome;
    const configPath = join(customHome, 'config.yaml');
    setExistingPaths([customHome, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) return mockConfig(configPath, { model: {} });
      throw new Error('ENOENT');
    });

    const result = await hermesAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].installDir).toBe(customHome);
  });

  it('extracts gateway info from platforms.api_server config', () => {
    const info = hermesAdapter.getGatewayInfo({
      platforms: {
        api_server: { host: '0.0.0.0', port: 9000 },
      },
    });
    expect(info).toEqual({
      host: '0.0.0.0',
      port: 9000,
    });
  });

  it('reports no gateway while the API server is disabled (the default)', () => {
    expect(hermesAdapter.getGatewayInfo({ platforms: {} })).toBeUndefined();
  });

  it('reads the API server from .env, gateway.api_server and platforms.api_server.extra', () => {
    const key = 'a3f9c27e5b1d4086f2e7';
    expect(hermesAdapter.getGatewayInfo({ API_SERVER_ENABLED: 'true', API_SERVER_KEY: key })).toEqual({ host: '127.0.0.1', port: 8642 });
    // The gateway ignores the API_SERVER_* block without a usable key
    expect(hermesAdapter.getGatewayInfo({ API_SERVER_ENABLED: 'true' })).toBeUndefined();
    expect(hermesAdapter.getGatewayInfo({ gateway: { api_server: { enabled: true, host: '0.0.0.0', port: 9000 } } }))
      .toEqual({ host: '0.0.0.0', port: 9000 });
    expect(hermesAdapter.getGatewayInfo({ platforms: { api_server: { extra: { host: '0.0.0.0' } } } }))
      .toEqual({ host: '0.0.0.0', port: 8642 });
    // Environment variables take precedence over config.yaml alongside a usable env key…
    expect(hermesAdapter.getGatewayInfo({ API_SERVER_HOST: '127.0.0.1', API_SERVER_KEY: key, gateway: { api_server: { host: '0.0.0.0' } } }))
      .toEqual({ host: '127.0.0.1', port: 8642 });
    // …otherwise config.yaml wins and the env host is only a fallback
    expect(hermesAdapter.getGatewayInfo({ API_SERVER_HOST: '0.0.0.0', gateway: { api_server: { host: '127.0.0.1', key } } }))
      .toEqual({ host: '127.0.0.1', port: 8642 });
    expect(hermesAdapter.getGatewayInfo({ API_SERVER_HOST: '0.0.0.0', gateway: { api_server: { enabled: true } } }))
      .toEqual({ host: '0.0.0.0', port: 8642 });
  });

  it('returns undefined gateway info when no platforms config', () => {
    const info = hermesAdapter.getGatewayInfo({});
    expect(info).toBeUndefined();
  });

  it('returns skills dir relative to install dir', () => {
    const skillsDir = hermesAdapter.getSkillsDir(hermesHome);
    expect(skillsDir).toBe(join(hermesHome, 'skills'));
  });

  it('returns correct config paths', () => {
    const paths = hermesAdapter.getConfigPaths();
    // A cli-config.yaml in HERMES_HOME is never read by Hermes; the
    // administrator-managed scope is
    expect(paths).toHaveLength(4);
    expect(paths).toContain('/etc/hermes/config.yaml');
    expect(paths).toContain('/etc/hermes/.env');
    expect(paths).not.toContain(join(hermesHome, 'cli-config.yaml'));
    expect(paths).toContain(join(hermesHome, 'config.yaml'));
    expect(paths).toContain(join(hermesHome, '.env'));
  });

  it('returns CLI command', () => {
    expect(hermesAdapter.getCLICommand!()).toBe('hermes');
  });

  it('returns probe manifest with expected structure', () => {
    const manifest = hermesAdapter.getProbeManifest!();
    expect(manifest.filePaths).toContain('~/.hermes/config.yaml');
    expect(manifest.filePaths).toContain('~/.hermes/.env');
    expect(manifest.globPatterns).toContain('~/.hermes/skills/**');
    expect(manifest.globPatterns).toContain('~/.hermes/optional-skills/**');
    expect(manifest.envPrefixes).toContain('HERMES_');
    expect(manifest.commands).toHaveLength(2);
    // `hermes version` installs dependencies in a fresh data root — only --version runs
    expect(manifest.commands.map(c => c.args.join(' '))).toEqual(['hermes', '--version']);
  });

  it('returns credential paths', () => {
    const paths = hermesAdapter.getCredentialPaths!(hermesHome);
    expect(paths).toContain(join(hermesHome, '.env'));
    expect(paths).toContain(join(hermesHome, 'credentials.json'));
  });

  it('returns memory file paths', () => {
    const paths = hermesAdapter.getMemoryFiles!(hermesHome);
    expect(paths).toContain(join(hermesHome, 'memory'));
    expect(paths).toContain(join(hermesHome, 'conversations.db'));
  });
});
