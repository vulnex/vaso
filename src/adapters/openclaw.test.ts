import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { openclawAdapter, getUserHomeDirs, allUsersCoverageWarning } from './openclaw.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';

// Mock modules
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

import { access, readdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { loadConfig } from '../core/config-loader.js';

const mockAccess = vi.mocked(access);
const mockReaddir = vi.mocked(readdir);
const mockExecFileSync = vi.mocked(execFileSync);
const mockLoadConfig = vi.mocked(loadConfig);

// Track which paths "exist"
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
    format: 'json' as const,
    filePath,
    data,
  };
}

describe('OpenClaw adapter', () => {
  const originalEnv = process.env;
  const originalPlatform = process.platform;

  beforeEach(() => {
    vi.resetAllMocks();
    process.env = { ...originalEnv };
    delete process.env.OPENCLAW_HOME;
    delete process.env.OPENCLAW_PROFILE;
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
    mockReaddir.mockResolvedValue([]);
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('returns empty array when nothing found', async () => {
    setExistingPaths([]);
    const result = await openclawAdapter.detect();
    expect(result).toEqual([]);
  });

  it('detects installation from ~/.openclaw config dir', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const configPath = join(openclawDir, 'openclaw.json');

    setExistingPaths([openclawDir, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, { version: '1.2.3' });
      }
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].agent).toBe('openclaw');
    expect(result[0].installDir).toBe(openclawDir);
    expect(result[0].version).toBe('1.2.3');
    expect(result[0].configFiles).toHaveLength(1);
  });

  it('discovers --profile state dirs (~/.openclaw-<name>) without OPENCLAW_PROFILE', async () => {
    const home = process.env.HOME || '/home/testuser';
    const profileDir = join(home, '.openclaw-work');
    const configPath = join(profileDir, 'openclaw.json');

    setExistingPaths([profileDir, configPath]);
    const dirent = (name: string) => ({ name, isDirectory: () => true, isFile: () => false, isSymbolicLink: () => false, parentPath: home });
    mockReaddir.mockImplementation((async (p: string) => (p === home
      ? [dirent('.openclaw-work'), dirent('.openclaw-default'), dirent('.openclaw-bad name')]
      : [])) as never);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, { version: '2.0.0' });
      }
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].installDir).toBe(profileDir);
    expect(result[0].profile).toBe('work');
  });

  it('detects CLI binary at system paths', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const configPath = join(openclawDir, 'openclaw.json');
    const cliBinPath = '/usr/local/bin/openclaw';

    setExistingPaths([openclawDir, configPath, cliBinPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, {});
      }
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe(cliBinPath);
  });

  it('detects CLI binary via which fallback', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const configPath = join(openclawDir, 'openclaw.json');

    setExistingPaths([openclawDir, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, {});
      }
      throw new Error('ENOENT');
    });
    mockExecFileSync.mockReturnValue('/custom/path/openclaw\n' as any);

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe('/custom/path/openclaw');
  });

  it('detects macOS .app bundle', async () => {
    const home = process.env.HOME || '/home/testuser';
    const appPath = '/Applications/OpenClaw.app';

    // Only the .app exists, no config dirs
    setExistingPaths([appPath]);

    // Override platform to darwin for this test
    Object.defineProperty(process, 'platform', { value: 'darwin', configurable: true });

    try {
      const result = await openclawAdapter.detect();
      expect(result).toHaveLength(1);
      expect(result[0].appBundle).toBe(appPath);
      expect(result[0].configFiles).toHaveLength(0);
    } finally {
      Object.defineProperty(process, 'platform', { value: originalPlatform, configurable: true });
    }
  });

  it('returns minimal installation when only CLI binary exists', async () => {
    const home = process.env.HOME || '/home/testuser';
    const cliBinPath = '/opt/homebrew/bin/openclaw';

    setExistingPaths([cliBinPath]);

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].cliBinary).toBe(cliBinPath);
    expect(result[0].configFiles).toHaveLength(0);
    expect(result[0].installDir).toBe(join(home, '.openclaw'));
  });

  it('reads OPENCLAW_HOME as a replacement home directory ($OPENCLAW_HOME/.openclaw)', async () => {
    process.env.OPENCLAW_HOME = '/opt/openclaw';
    const dir = join('/opt/openclaw', '.openclaw');
    const configPath = join(dir, 'openclaw.json');

    setExistingPaths([dir, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, { version: '3.0.0' });
      }
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].installDir).toBe(dir);
    expect(result[0].version).toBe('3.0.0');
  });

  it('reads OPENCLAW_STATE_DIR as the state dir and OPENCLAW_CONFIG_PATH as its config file', async () => {
    process.env.OPENCLAW_STATE_DIR = '/srv/oc-state';
    process.env.OPENCLAW_CONFIG_PATH = '/etc/oc/main.json5';

    setExistingPaths(['/srv/oc-state', '/etc/oc/main.json5']);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === '/etc/oc/main.json5') return mockConfig(path as string, { version: '3.1.0' });
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].installDir).toBe('/srv/oc-state');
    expect(result[0].configFiles.map(c => c.filePath)).toEqual(['/etc/oc/main.json5']);
    delete process.env.OPENCLAW_STATE_DIR;
    delete process.env.OPENCLAW_CONFIG_PATH;
  });

  it('does not set user field when allUsers is not set', async () => {
    const home = process.env.HOME || '/home/testuser';
    const openclawDir = join(home, '.openclaw');
    const configPath = join(openclawDir, 'openclaw.json');

    setExistingPaths([openclawDir, configPath]);
    mockLoadConfig.mockImplementation(async (path) => {
      if (path === configPath) {
        return mockConfig(configPath, {});
      }
      throw new Error('ENOENT');
    });

    const result = await openclawAdapter.detect();
    expect(result).toHaveLength(1);
    expect(result[0].user).toBeUndefined();
  });
});

describe('OpenClaw getGatewayInfo (2026.x schema)', () => {
  const info = (gateway: Record<string, unknown>) => openclawAdapter.getGatewayInfo!({ gateway });
  it('resolves gateway.bind modes to a listen address', () => {
    expect(info({ bind: 'loopback' })?.host).toBe('127.0.0.1');
    expect(info({ bind: 'lan' })?.host).toBe('0.0.0.0');
    expect(info({ bind: 'custom', customBindHost: '10.0.0.5' })?.host).toBe('10.0.0.5');
    expect(info({ bind: 'auto' })?.host).toBeUndefined();
    expect(info({ host: '127.0.0.1', bind: 'lan' })?.host).toBe('127.0.0.1');
  });
  it('reads tls as an object or a boolean', () => {
    expect(info({ tls: { enabled: true } })?.tls).toBe(true);
    expect(info({ tls: { enabled: false } })?.tls).toBe(false);
    expect(info({ tls: true })?.tls).toBe(true);
  });
});

describe('getUserHomeDirs', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('returns current user home when allUsers is false', async () => {
    const dirs = await getUserHomeDirs(false);
    expect(dirs).toHaveLength(1);
    expect(dirs[0].home).toBeTruthy();
  });

  it('returns current user home when allUsers is true but not root', async () => {
    // process.getuid() won't be 0 in test env
    const dirs = await getUserHomeDirs(true);
    expect(dirs).toHaveLength(1);
  });

  it('returns current user home when allUsers is undefined', async () => {
    const dirs = await getUserHomeDirs();
    expect(dirs).toHaveLength(1);
  });

  // A --sudo remote scan runs the probe as root while the CLI runs as a normal
  // user: the scanned host's privilege decides, not the local process uid.
  const snapshot = (isRoot: boolean) => new SnapshotFSProvider({
    version: 1, hostname: 'h', platform: 'linux', homedir: isRoot ? '/root' : '/home/scanner', timestamp: '2026-09-29T00:00:00Z',
    privilege: { uid: isRoot ? 0 : 1000, username: isRoot ? 'root' : 'scanner', isRoot, sudoAvailable: true, escalated: isRoot, scannedUsers: [], skippedPaths: [] },
    files: {
      '/home/alice/.picoclaw/config.json': { content: '{}', mode: 0o100600, exists: true },
      '/home/bob/.zeroclaw/config.toml': { content: '', mode: 0o100600, exists: true },
      '/root/.bashrc': { content: '', mode: 0o100644, exists: true },
    },
    directories: { '/home': ['alice/', 'bob/'] }, directoryModes: {}, commandOutputs: {}, env: {},
  } as unknown as ConstructorParameters<typeof SnapshotFSProvider>[0]);

  it('enumerates every user on a root (--sudo) snapshot', async () => {
    const dirs = await getUserHomeDirs(true, snapshot(true));
    expect(dirs.map(d => d.user).sort()).toEqual(['alice', 'bob', 'root']);
  });

  it('keeps to the probe user on a non-root snapshot', async () => {
    const dirs = await getUserHomeDirs(true, snapshot(false));
    expect(dirs).toEqual([{ home: '/home/scanner', user: 'scanner' }]);
  });

  it('warns that --all-users covered one home when the scan is not privileged', () => {
    expect(allUsersCoverageWarning(snapshot(false))).toBe(
      "--all-users needs root to read other users' homes; only /home/scanner was covered (run as root, or add --sudo for remote hosts)",
    );
    expect(allUsersCoverageWarning(snapshot(true))).toBeUndefined();
  });
});
