import { describe, it, expect } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import type { ParsedConfig, ScanContext } from '../core/types.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { containerEnvironment } from './openclaw-bind.js';
import { openclawAdapter } from './openclaw.js';
import { cfg001 } from '../checks/config/cfg-001-gateway-binding.js';
import { cfg004 } from '../checks/config/cfg-004-tls-config.js';
import { oc008 } from '../checks/openclaw/oc-008-dangerous-gateway-overrides.js';
import { extractPosture, findDowngrades } from '../checks/openclaw/posture.js';

/** A local-scan FSProvider whose container markers are under test control. */
function hostFs(opts: { files?: Record<string, string>; env?: Record<string, string>; platform?: 'linux' | 'darwin' } = {}): FSProvider {
  const base = new LocalFSProvider();
  const files = opts.files ?? {};
  return Object.assign(Object.create(base) as FSProvider, {
    kind: 'local',
    platform: opts.platform ?? 'linux',
    getEnv: (k: string) => opts.env?.[k],
    access: async (p: string) => p in files,
    readFile: async (p: string) => {
      if (p in files) return files[p];
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    },
  });
}

function snapshotFs(files: Record<string, string> = {}, directories: Record<string, string[]> = {}): SnapshotFSProvider {
  return new SnapshotFSProvider({
    version: 1, hostname: 'h', platform: 'linux', homedir: '/home/u', timestamp: '2026-11-08T00:00:00Z',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: [], skippedPaths: [] },
    files: Object.fromEntries(Object.entries(files).map(([p, content]) => [p, { content, mode: 0o100600, exists: true }])),
    directories, directoryModes: {}, commandOutputs: {}, env: {},
  } as unknown as ConstructorParameters<typeof SnapshotFSProvider>[0]);
}

function ctxFor(data: Record<string, unknown>, fs: FSProvider): ScanContext {
  const config: ParsedConfig = { raw: JSON.stringify(data), format: 'json', filePath: '/home/u/.openclaw/openclaw.json', data };
  return {
    installation: { agent: 'openclaw', installDir: '/home/u/.openclaw', configFiles: [config], gateway: openclawAdapter.getGatewayInfo(data) },
    configs: [config], platform: 'linux', fs,
  };
}

describe('OpenClaw container detection (isContainerEnvironment markers)', () => {
  it('finds /.dockerenv, /run/.containerenv, a container cgroup and Fly machines', async () => {
    expect(await containerEnvironment(hostFs({ files: { '/.dockerenv': '' } }))).toBe(true);
    expect(await containerEnvironment(hostFs({ files: { '/run/.containerenv': '' } }))).toBe(true);
    expect(await containerEnvironment(hostFs({ files: { '/proc/1/cgroup': '0::/kubepods/besteffort/pod1\n' } }))).toBe(true);
    expect(await containerEnvironment(hostFs({ env: { FLY_MACHINE_ID: 'm', FLY_APP_NAME: 'a' } }))).toBe(true);
  });

  it('is false on a plain host and unknown on a snapshot', async () => {
    expect(await containerEnvironment(hostFs({ files: { '/proc/1/cgroup': '0::/init.scope\n' } }))).toBe(false);
    expect(await containerEnvironment(snapshotFs())).toBeUndefined();
  });
});

describe('g4-F1: gateway.bind "auto" is loopback outside containers', () => {
  const auto = { gateway: { mode: 'local', bind: 'auto', auth: { mode: 'token', token: '${OPENCLAW_GATEWAY_TOKEN}' } } };

  it('CFG-001: informational and not fixable on a host that is not a container', async () => {
    const r = await cfg001.run(ctxFor(auto, hostFs()));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
    expect(r.fixable).toBeFalsy();
    expect(r.evidence?.[0].detail).toContain('no container detected');
  });

  it('CFG-001: informational on a snapshot, where the container question is open', async () => {
    const r = await cfg001.run(ctxFor(auto, snapshotFs()));
    expect(r.severity).toBe('info');
    expect(r.evidence?.[0].detail).toContain("can't be verified");
  });

  it('CFG-001: critical and fixable inside a container', async () => {
    const r = await cfg001.run(ctxFor(auto, hostFs({ files: { '/.dockerenv': '' } })));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.fixable).toBe(true);
  });

  it('"lan" stays critical everywhere', async () => {
    const r = await cfg001.run(ctxFor({ gateway: { bind: 'lan' } }, hostFs()));
    expect(r.severity).toBe('critical');
  });

  it('CFG-004: no TLS finding for "auto" outside a container (resolved or unknown)', async () => {
    const local = ctxFor(auto, hostFs());
    local.installation.gateway = { host: '127.0.0.1' };
    expect((await cfg004.run(local)).passed).toBe(true);
    expect((await cfg004.run(ctxFor(auto, snapshotFs()))).passed).toBe(true);
  });

  it('OC-008: severity tier follows the container question', async () => {
    const data = { ...auto, gateway: { ...auto.gateway, tools: { allow: ['exec'] } } };
    expect((await oc008.run(ctxFor(data, hostFs()))).severity).toBe('warning');
    expect((await oc008.run(ctxFor(data, hostFs({ files: { '/.dockerenv': '' } })))).severity).toBe('critical');
  });

  it('OC-001/OC-005 posture: loopback → "auto" is a downgrade only inside a container', () => {
    const base = extractPosture({ gateway: { bind: 'loopback' } });
    expect(findDowngrades(base, extractPosture({ gateway: { bind: 'auto' } }, undefined, false))).toEqual([]);
    expect(findDowngrades(base, extractPosture({ gateway: { bind: 'auto' } }, undefined, undefined))).toEqual([]);
    expect(findDowngrades(base, extractPosture({ gateway: { bind: 'auto' } }, undefined, true))[0]).toContain('0.0.0.0');
  });
});

describe('g4-F2: only files OpenClaw reads are scanned', () => {
  it('ignores a stray config.json / config.yaml / gateway.yaml and keeps the gateway from openclaw.json', async () => {
    const fs = snapshotFs({
      '/home/u/.openclaw/openclaw.json': JSON.stringify({ gateway: { bind: 'lan', port: 18789 } }),
      '/home/u/.openclaw/config.json': JSON.stringify({ gateway: { port: 9999 } }),
      '/home/u/.openclaw/config.yaml': 'gateway:\n  host: 0.0.0.0\n  bind: lan\nsandbox: false\n',
      '/home/u/.openclaw/gateway.yaml': 'host: 0.0.0.0\n',
      '/home/u/.openclaw/.env': 'OPENCLAW_GATEWAY_TOKEN=x\n',
    }, {
      '/home/u': ['.openclaw/'],
      '/home/u/.openclaw': ['openclaw.json', 'config.json', 'config.yaml', 'gateway.yaml', '.env'],
    });
    const [inst] = await openclawAdapter.detect({ fs });
    expect(inst.configFiles.map(c => c.filePath).sort()).toEqual(['/home/u/.openclaw/.env', '/home/u/.openclaw/openclaw.json']);
    expect(inst.gateway).toMatchObject({ host: '0.0.0.0', port: 18789 });
  });

  it('leaves "auto" unresolved on a snapshot', async () => {
    const fs = snapshotFs({ '/home/u/.openclaw/openclaw.json': JSON.stringify({ gateway: { bind: 'auto' } }) }, { '/home/u': ['.openclaw/'], '/home/u/.openclaw': ['openclaw.json'] });
    const [inst] = await openclawAdapter.detect({ fs });
    expect(inst.gateway?.host).toBeUndefined();
  });

  it('keeps stray files out of the probe manifest', () => {
    const m = openclawAdapter.getProbeManifest!();
    const all = [...m.filePaths, ...(m.globPatterns ?? [])];
    expect(all.some(p => /\/\.(openclaw|clawdbot|moltbot)[^/]*\/(config\.(yaml|json)|gateway\.yaml)$/.test(p))).toBe(false);
  });
});

describe('g4-F3: OpenClaw mcp.servers in vaso mcp discovery', () => {
  it('finds enabled servers in openclaw.json (JSON5), honouring transport and enabled: false', async () => {
    const { MCPDiscovery } = await import('../mcp/discovery.js');
    const fs = snapshotFs({
      '/home/u/.openclaw/openclaw.json': `{
        // JSON5, as OpenClaw writes it
        mcp: { servers: {
          fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/'] },
          web: { url: 'http://mcp.example.com/events', transport: 'sse' },
          off: { command: 'node', args: ['x.js'], enabled: false },
        } },
      }`,
    }, { '/home/u': ['.openclaw/'], '/home/u/.openclaw': ['openclaw.json'] });
    const result = await new MCPDiscovery(fs).discover('linux');
    const oc = result.configs.find(c => c.source === 'OpenClaw');
    expect(oc?.filePath).toBe('/home/u/.openclaw/openclaw.json');
    expect(oc?.servers.map(s => s.name).sort()).toEqual(['fs', 'web']);
    expect(oc?.servers.find(s => s.name === 'web')?.transport).toBe('sse');
  });
});
