import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('node:fs/promises', () => ({
  readFile: vi.fn(),
  writeFile: vi.fn(),
  mkdir: vi.fn(),
  unlink: vi.fn(),
  chmod: vi.fn(),
  access: vi.fn(),
}));

vi.mock('node:os', () => ({
  homedir: vi.fn(() => '/home/testuser'),
}));

vi.mock('node:child_process', () => ({
  execFileSync: vi.fn(),
}));

import { readFile, writeFile, mkdir, unlink, chmod, access } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import {
  installPlugin,
  uninstallPlugin,
  getPluginStatus,
  resolveVasoBinaryPath,
  loadPluginConfig,
  savePluginConfig,
} from './installer.js';

const mockReadFile = vi.mocked(readFile);
const mockWriteFile = vi.mocked(writeFile);
const mockMkdir = vi.mocked(mkdir);
const mockUnlink = vi.mocked(unlink);
const mockChmod = vi.mocked(chmod);
const mockAccess = vi.mocked(access);
const mockExecFileSync = vi.mocked(execFileSync);

describe('installPlugin', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockMkdir.mockResolvedValue(undefined);
    mockWriteFile.mockResolvedValue(undefined);
    mockChmod.mockResolvedValue(undefined);
    // Default: plugin file doesn't exist
    mockAccess.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }));
  });

  it('creates directory, writes plugin file and manifest', async () => {
    const result = await installPlugin('openclaw', { vasoBinaryPath: '/usr/bin/vaso' });

    expect(mockMkdir).toHaveBeenCalled();
    expect(mockWriteFile).toHaveBeenCalledTimes(2); // plugin + manifest
    expect(mockChmod).toHaveBeenCalled();
    expect(result.pluginPath).toContain('vaso-security.mjs');
    expect(result.manifestPath).toContain('vaso-plugin-manifest.json');
  });

  it('throws when plugin exists without force', async () => {
    mockAccess.mockResolvedValueOnce(undefined); // file exists
    await expect(installPlugin('openclaw')).rejects.toThrow('already installed');
  });

  it('overwrites with force flag', async () => {
    mockAccess.mockResolvedValueOnce(undefined); // file exists
    const result = await installPlugin('openclaw', { force: true, vasoBinaryPath: '/usr/bin/vaso' });
    expect(result.pluginPath).toContain('vaso-security.mjs');
    expect(mockWriteFile).toHaveBeenCalledTimes(2);
  });

  it('uses provided vasoBinaryPath in generated content', async () => {
    await installPlugin('nanoclaw', { vasoBinaryPath: '/custom/vaso' });

    const writeCall = mockWriteFile.mock.calls[0];
    const content = writeCall[1] as string;
    expect(content).toContain('/custom/vaso');
  });
});

describe('uninstallPlugin', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockUnlink.mockResolvedValue(undefined);
  });

  it('removes plugin and manifest files', async () => {
    await uninstallPlugin('openclaw');
    expect(mockUnlink).toHaveBeenCalledTimes(2);
  });

  it('ignores ENOENT when files do not exist', async () => {
    mockUnlink.mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }));
    await expect(uninstallPlugin('openclaw')).resolves.toBeUndefined();
  });
});

describe('getPluginStatus', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('reports installed=true when file exists', async () => {
    mockAccess.mockResolvedValue(undefined);
    mockReadFile.mockResolvedValue(JSON.stringify({
      agent: 'openclaw',
      vasoVersion: '0.1.0',
      vasoBinaryPath: '/usr/bin/vaso',
      installedAt: '2026-01-01T00:00:00Z',
      pluginPath: '/home/testuser/.openclaw/plugins/vaso-security.mjs',
    }) as any);

    const results = await getPluginStatus('openclaw');
    expect(results).toHaveLength(1);
    expect(results[0].installed).toBe(true);
    expect(results[0].vasoBinaryPath).toBe('/usr/bin/vaso');
    expect(results[0].installedAt).toBe('2026-01-01T00:00:00Z');
  });

  it('reports installed=false when file missing', async () => {
    mockAccess.mockRejectedValue(new Error('ENOENT'));
    const results = await getPluginStatus('openclaw');
    expect(results).toHaveLength(1);
    expect(results[0].installed).toBe(false);
    expect(results[0].pluginPath).toBeUndefined();
  });

  it('handles corrupt manifest gracefully', async () => {
    mockAccess.mockResolvedValue(undefined);
    mockReadFile.mockRejectedValue(new Error('parse error'));

    const results = await getPluginStatus('openclaw');
    expect(results).toHaveLength(1);
    expect(results[0].installed).toBe(true);
    expect(results[0].vasoBinaryPath).toBeUndefined();
  });

  it('returns all agents when no filter given', async () => {
    mockAccess.mockRejectedValue(new Error('ENOENT'));
    const results = await getPluginStatus();
    expect(results).toHaveLength(3); // openclaw, nanoclaw, picoclaw
  });
});

describe('resolveVasoBinaryPath', () => {
  const originalArgv = process.argv;

  beforeEach(() => {
    vi.resetAllMocks();
  });

  afterEach(() => {
    process.argv = originalArgv;
  });

  it('returns process.argv[1] when available', () => {
    process.argv = ['node', '/usr/local/bin/vaso', 'scan'];
    const result = resolveVasoBinaryPath();
    expect(result).toBe('/usr/local/bin/vaso');
  });

  it('falls back to which when argv[1] empty', () => {
    process.argv = ['node', ''];
    mockExecFileSync.mockReturnValue('/usr/bin/vaso\n' as any);
    const result = resolveVasoBinaryPath();
    expect(result).toBe('/usr/bin/vaso');
  });

  it('falls back to "vaso" when all else fails', () => {
    process.argv = ['node', ''];
    mockExecFileSync.mockImplementation(() => { throw new Error('not found'); });
    const result = resolveVasoBinaryPath();
    expect(result).toBe('vaso');
  });
});

describe('loadPluginConfig / savePluginConfig', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mockMkdir.mockResolvedValue(undefined);
    mockWriteFile.mockResolvedValue(undefined);
  });

  it('returns defaults when config file missing', async () => {
    mockReadFile.mockRejectedValue(new Error('ENOENT'));
    const config = await loadPluginConfig();
    expect(config.blockOnCritical).toBe(true);
    expect(config.blockOnWarning).toBe(false);
    expect(config.timeout).toBe(30_000);
    expect(config.excludeChecks).toEqual([]);
  });

  it('merges saved values over defaults', async () => {
    mockReadFile.mockResolvedValue(JSON.stringify({ timeout: 60000 }) as any);
    const config = await loadPluginConfig();
    expect(config.timeout).toBe(60000);
    expect(config.blockOnCritical).toBe(true); // default preserved
  });

  it('saves config and creates directory', async () => {
    await savePluginConfig({ blockOnCritical: false, blockOnWarning: true, timeout: 5000, excludeChecks: ['CFG-001'] });
    expect(mockMkdir).toHaveBeenCalled();
    expect(mockWriteFile).toHaveBeenCalledTimes(1);
    const written = JSON.parse(mockWriteFile.mock.calls[0][1] as string);
    expect(written.blockOnCritical).toBe(false);
  });
});
