import { describe, it, expect, vi } from 'vitest';
import type { ScanContext, ParsedConfig, AgentInstallation } from '../../core/types.js';
import type { FSProvider } from '../../core/fs-provider.js';
import { hermesChecks } from './index.js';
import { cfg001 } from '../config/cfg-001-gateway-binding.js';
import { net001 } from '../network/net-001-gateway-exposure.js';

/**
 * The administrator-managed scope (/etc/hermes, hermes_cli/managed_scope.py):
 * config.yaml deep-merged over the user's per leaf, .env loaded last with
 * override. Checks judge the effective value.
 */

const HOME = '/home/test/.hermes';
const user = (name: string, data: Record<string, unknown>, raw = ''): ParsedConfig =>
  ({ raw, format: name === '.env' ? 'env' : 'yaml', filePath: `${HOME}/${name}`, data });
const managed = (name: string, data: Record<string, unknown>, raw = ''): ParsedConfig =>
  ({ raw, format: name === '.env' ? 'env' : 'yaml', filePath: `/etc/hermes/${name}`, data, managed: true });

function makeFs(modes: Record<string, number> = {}, dirs: string[] = [], env: Record<string, string> = {}): FSProvider {
  return {
    access: vi.fn(async (p: string) => p in modes),
    stat: vi.fn(async (p: string) => {
      if (p in modes) return { mode: modes[p], isFile: () => !dirs.includes(p), isDirectory: () => dirs.includes(p) };
      throw Object.assign(new Error(`ENOENT ${p}`), { code: 'ENOENT' });
    }),
    readFile: vi.fn(async () => { throw new Error('not used'); }),
    readdir: vi.fn(async () => []),
    readdirEntries: vi.fn(async () => []),
    realpath: vi.fn(async (p: string) => p),
    exec: vi.fn(),
    execSync: vi.fn(() => { throw new Error('not found'); }),
    homedir: () => '/home/test',
    getEnv: vi.fn((k: string) => env[k]),
    platform: 'linux',
  } as FSProvider;
}

function ctx(configs: ParsedConfig[], opts: { fs?: FSProvider; version?: string } = {}): ScanContext {
  const installation: AgentInstallation = { agent: 'hermes', installDir: HOME, configFiles: configs, version: opts.version };
  return { installation, configs, platform: 'linux', fs: opts.fs ?? makeFs() };
}

const check = (id: string) => hermesChecks.find(c => c.id === id)!;

describe('HM-008 with an administrator-managed config', () => {
  it('a managed approvals.mode turns the user\'s "off" into an overridden (info) finding', async () => {
    const r = await check('HM-008').run(ctx([
      user('config.yaml', { approvals: { mode: 'off' } }),
      managed('config.yaml', { approvals: { mode: 'manual' } }),
    ]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
    expect(r.evidence![0].detail).toContain('overridden by the administrator-managed /etc/hermes/config.yaml');
  });

  it('a managed scalar over the approvals mapping replaces it too', async () => {
    const r = await check('HM-008').run(ctx([
      user('config.yaml', { approvals: { mode: 'off' } }),
      managed('config.yaml', { approvals: 'manual' }),
    ]));
    expect(r.severity).toBe('info');
  });

  it('a managed null over the mapping is ignored (Hermes _deep_merge)', async () => {
    const r = await check('HM-008').run(ctx([
      user('config.yaml', { approvals: { mode: 'off' } }),
      managed('config.yaml', { approvals: null }),
    ]));
    expect(r.severity).toBe('critical');
  });

  it('a managed key elsewhere leaves the user\'s value live', async () => {
    const r = await check('HM-008').run(ctx([
      user('config.yaml', { approvals: { mode: 'off' } }),
      managed('config.yaml', { approvals: { cron_mode: 'deny' } }),
    ]));
    expect(r.severity).toBe('critical');
  });

  it('reports an insecure managed value against the managed file', async () => {
    const r = await check('HM-008').run(ctx([
      user('config.yaml', { approvals: { mode: 'manual' } }),
      managed('config.yaml', { approvals: { mode: 'off' } }),
    ]));
    expect(r.severity).toBe('critical');
    expect(r.evidence!.map(e => e.file)).toEqual(['/etc/hermes/config.yaml']);
  });

  it('a managed HERMES_YOLO_MODE beats the user\'s .env', async () => {
    const r = await check('HM-008').run(ctx([
      user('.env', { HERMES_YOLO_MODE: '1' }),
      managed('.env', { HERMES_YOLO_MODE: 'false' }),
    ]));
    expect(r.severity).toBe('info');
  });
});

describe('HM-009 with an administrator-managed config', () => {
  const fs = makeFs({ [`${HOME}/bin/tirith`]: 0o755 }, [], {});
  it('a managed tirith_enabled: true wins over the user\'s false', async () => {
    const r = await check('HM-009').run(ctx([
      user('config.yaml', { security: { tirith_enabled: false } }),
      managed('config.yaml', { security: { tirith_enabled: true } }),
    ], { fs }));
    expect(r.passed).toBe(true);
  });

  it('a managed tirith_enabled: false is reported against the managed file', async () => {
    const r = await check('HM-009').run(ctx([
      user('config.yaml', { security: { tirith_enabled: true } }),
      managed('config.yaml', { security: { tirith_enabled: false } }),
    ], { fs }));
    expect(r.passed).toBe(false);
    expect(r.evidence!.map(e => e.file)).toEqual(['/etc/hermes/config.yaml']);
  });

  it('a managed TIRITH_ENABLED in the managed .env beats the user\'s', async () => {
    const r = await check('HM-009').run(ctx([
      user('config.yaml', {}),
      user('.env', { TIRITH_ENABLED: 'false' }),
      managed('.env', { TIRITH_ENABLED: 'true' }),
    ], { fs }));
    expect(r.passed).toBe(true);
  });
});

describe('HM-006 / HM-010 with an administrator-managed config', () => {
  it('a user http:// base_url the managed config replaces is info; the managed one is live', async () => {
    const r = await check('HM-006').run(ctx([
      user('config.yaml', { model: { base_url: 'http://10.0.0.5:8000/v1' } }),
      managed('config.yaml', { model: { base_url: 'https://openrouter.ai/api/v1' } }),
    ]));
    expect(r.severity).toBe('info');
    const live = await check('HM-006').run(ctx([
      user('config.yaml', { model: { base_url: 'https://openrouter.ai/api/v1' } }),
      managed('config.yaml', { model: { base_url: 'http://10.0.0.5:8000/v1' } }),
    ]));
    expect(live.severity).toBe('critical');
    expect(live.evidence!.map(e => e.file)).toEqual(['/etc/hermes/config.yaml']);
  });

  it('an MCP server whose command the managed layer replaces is info', async () => {
    const r = await check('HM-010').run(ctx([
      user('config.yaml', { mcp_servers: { fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem'] } } }),
      managed('config.yaml', { mcp_servers: { fs: { args: ['-y', '@modelcontextprotocol/server-filesystem@2025.8.21'] } } }),
    ]));
    expect(r.severity).toBe('info');
  });
});

describe('API server (HM-004, CFG-001, NET-001) with an administrator-managed .env', () => {
  // 0.8.0: before the start-up key guards, so a keyless server starts open
  const old = '0.8.0';
  it('a managed loopback host wins over the user\'s 0.0.0.0', async () => {
    const configs = [
      user('.env', { API_SERVER_ENABLED: 'true', API_SERVER_HOST: '0.0.0.0' }, 'API_SERVER_ENABLED=true\nAPI_SERVER_HOST=0.0.0.0'),
      managed('.env', { API_SERVER_HOST: '127.0.0.1' }, 'API_SERVER_HOST=127.0.0.1'),
    ];
    const c = ctx(configs, { version: old });
    c.installation.gateway = { host: '127.0.0.1', port: 8642 };
    expect((await check('HM-004').run(c)).passed).toBe(true);
    expect((await cfg001.run(c)).passed).toBe(true);
    expect((await net001.run(c)).passed).toBe(true);
  });

  it('a managed 0.0.0.0 is reported against the managed file', async () => {
    const configs = [
      user('.env', { API_SERVER_ENABLED: 'true', API_SERVER_HOST: '127.0.0.1' }, 'API_SERVER_ENABLED=true\nAPI_SERVER_HOST=127.0.0.1'),
      managed('.env', { API_SERVER_HOST: '0.0.0.0' }, 'API_SERVER_HOST=0.0.0.0'),
    ];
    const c = ctx(configs, { version: old });
    c.installation.gateway = { host: '0.0.0.0', port: 8642 };
    const hm = await check('HM-004').run(c);
    expect(hm.passed).toBe(false);
    expect(hm.evidence![0].file).toBe('/etc/hermes/.env');
    const cfg = await cfg001.run(c);
    expect(cfg.passed).toBe(false);
    expect(cfg.evidence!.map(e => e.file)).toEqual(['/etc/hermes/.env']);
  });
});

describe('HM-002 on the administrator-managed .env', () => {
  const env = managed('.env', { OPENROUTER_API_KEY: 'sk-or-v1-x' }, 'OPENROUTER_API_KEY=sk-or-v1-x');
  it('group-readable is by design (every Hermes user reads it)', async () => {
    const r = await check('HM-002').run(ctx([env], { fs: makeFs({ '/etc/hermes/.env': 0o640 }) }));
    expect(r.passed).toBe(true);
  });
  it('world-readable with secrets is flagged', async () => {
    const r = await check('HM-002').run(ctx([env], { fs: makeFs({ '/etc/hermes/.env': 0o644 }) }));
    expect(r.passed).toBe(false);
    expect(r.evidence![0].detail).toContain('world-readable');
  });
});

describe('HM-011 administrator-managed scope writable by others', () => {
  it('passes when there is no managed scope', async () => {
    const r = await check('HM-011').run(ctx([], { fs: makeFs() }));
    expect(r.passed).toBe(true);
  });

  it('passes for the vendor layout (root dir 0755, config.yaml 0644, .env 0640)', async () => {
    const r = await check('HM-011').run(ctx([], {
      fs: makeFs({ '/etc/hermes': 0o755, '/etc/hermes/config.yaml': 0o644, '/etc/hermes/.env': 0o640 }, ['/etc/hermes']),
    }));
    expect(r.passed).toBe(true);
  });

  it('flags a world-writable managed dir and a group-writable config.yaml (critical)', async () => {
    const r = await check('HM-011').run(ctx([], {
      fs: makeFs({ '/etc/hermes': 0o777, '/etc/hermes/config.yaml': 0o664 }, ['/etc/hermes']),
    }));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.evidence!.map(e => e.file)).toEqual(['/etc/hermes', '/etc/hermes/config.yaml']);
  });

  it('follows $HERMES_MANAGED_DIR instead of /etc/hermes', async () => {
    const r = await check('HM-011').run(ctx([], {
      fs: makeFs({ '/etc/hermes': 0o777, '/opt/it/hermes': 0o757 }, ['/etc/hermes', '/opt/it/hermes'], { HERMES_MANAGED_DIR: '/opt/it/hermes' }),
    }));
    expect(r.evidence!.map(e => e.file)).toEqual(['/opt/it/hermes']);
  });

  it('ignores a relative $HERMES_MANAGED_DIR (resolved against the daemon\'s cwd) and an absent one', async () => {
    const rel = await check('HM-011').run(ctx([], {
      fs: makeFs({ '/etc/hermes': 0o777 }, ['/etc/hermes'], { HERMES_MANAGED_DIR: 'managed' }),
    }));
    expect(rel.passed).toBe(true);
    const missing = await check('HM-011').run(ctx([], {
      fs: makeFs({ '/etc/hermes': 0o777 }, ['/etc/hermes'], { HERMES_MANAGED_DIR: '/nonexistent' }),
    }));
    expect(missing.passed).toBe(true);
  });
});

describe('Hermes probe manifest', () => {
  it('collects the managed scope at /etc/hermes and $HERMES_MANAGED_DIR, with directory modes for HM-011', async () => {
    const { hermesAdapter } = await import('../../adapters/hermes.js');
    const m = hermesAdapter.getProbeManifest!();
    expect(m.filePaths).toEqual(expect.arrayContaining([
      '/etc/hermes/config.yaml', '/etc/hermes/.env', '${HERMES_MANAGED_DIR}/config.yaml', '${HERMES_MANAGED_DIR}/.env',
    ]));
    expect(m.systemDirListings).toContain('/etc/hermes');
    expect(m.directoryListings).toContain('${HERMES_MANAGED_DIR}');
    expect(m.envPrefixes).toContain('HERMES_');
  });
});
