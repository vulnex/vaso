import { describe, it, expect } from 'vitest';
import type { FSProvider } from '../core/fs-provider.js';
import type { ParsedConfig, ScanContext } from '../core/types.js';
import { SnapshotFSProvider } from '../core/snapshot-fs-provider.js';
import { LocalFSProvider } from '../core/local-fs-provider.js';
import { containerEnvironment } from './openclaw-bind.js';
import { openclawAdapter } from './openclaw.js';
import { cfg001 } from '../checks/config/cfg-001-gateway-binding.js';
import { cfg004 } from '../checks/config/cfg-004-tls-config.js';
import { net001 } from '../checks/network/net-001-gateway-exposure.js';
import { buildProbeManifest } from '../core/manifest-builder.js';
import { oc008, openclawGatewayExposed } from '../checks/openclaw/oc-008-dangerous-gateway-overrides.js';
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

/** A snapshot from a probe run with the current manifest: the container
 *  markers are collected, absent ones recorded as `exists: false`. */
function markerSnapshot(opts: { config?: Record<string, unknown>; sentinel?: string; cgroup?: string; env?: Record<string, string> } = {}): SnapshotFSProvider {
  const files: Record<string, { content: string; mode: number; exists: boolean; contentOmitted?: boolean; omitted?: string }> = {
    '/proc/1/cgroup': opts.cgroup === undefined ? { content: '', mode: 0, exists: false } : { content: opts.cgroup, mode: 0o444, exists: true },
  };
  if (opts.sentinel) files[opts.sentinel] = { content: '', mode: 0o755, exists: true, contentOmitted: true, omitted: 'metadata' };
  if (opts.config) files['/home/u/.openclaw/openclaw.json'] = { content: JSON.stringify(opts.config), mode: 0o600, exists: true };
  return new SnapshotFSProvider({
    version: 1, hostname: 'h', platform: 'linux', homedir: '/home/u', timestamp: '2026-11-09T00:00:00Z',
    privilege: { uid: 1000, username: 'u', isRoot: false, sudoAvailable: false, escalated: false, scannedUsers: [], skippedPaths: [] },
    files, directories: { '/home/u': ['.openclaw/'], '/home/u/.openclaw': ['openclaw.json'] }, directoryModes: {}, commandOutputs: {}, env: opts.env ?? {},
  } as unknown as ConstructorParameters<typeof SnapshotFSProvider>[0]);
}

describe('dt20 g4-F3: remote scans decide "auto" from the collected container markers', () => {
  const auto = { gateway: { mode: 'local', bind: 'auto', auth: { mode: 'token', token: '${OPENCLAW_GATEWAY_TOKEN}' } } };

  it('reads the same markers from a snapshot as from the local host', async () => {
    expect(await containerEnvironment(markerSnapshot({ env: { FLY_MACHINE_ID: 'set', FLY_APP_NAME: 'set' } }))).toBe(true);
    expect(await containerEnvironment(markerSnapshot({ sentinel: '/.dockerenv' }))).toBe(true);
    expect(await containerEnvironment(markerSnapshot({ sentinel: '/run/.containerenv' }))).toBe(true);
    expect(await containerEnvironment(markerSnapshot({ cgroup: '12:pids:/docker/0123abcd\n' }))).toBe(true);
    // both Fly variables are required, as upstream
    expect(await containerEnvironment(markerSnapshot({ env: { FLY_MACHINE_ID: 'set' } }))).toBe(false);
    expect(await containerEnvironment(markerSnapshot({ cgroup: '0::/init.scope\n' }))).toBe(false);
    expect(await containerEnvironment(markerSnapshot())).toBe(false);
  });

  it('stays undecided for a snapshot whose manifest did not ask for the markers', async () => {
    expect(await containerEnvironment(snapshotFs({ '/.dockerenv': '' }))).toBeUndefined();
  });

  it('CFG-001 / NET-001 / CFG-004 judge a containerised remote host like the local scan', async () => {
    const fs = markerSnapshot({ config: auto, env: { FLY_MACHINE_ID: 'set', FLY_APP_NAME: 'set' } });
    const [inst] = await openclawAdapter.detect({ fs });
    expect(inst.gateway?.host).toBe('0.0.0.0');
    const c = { installation: inst, configs: inst.configFiles, platform: 'linux' as const, fs };
    expect(await cfg001.run(c)).toMatchObject({ passed: false, severity: 'critical', fixable: true });
    expect(await net001.run(c)).toMatchObject({ passed: false, severity: 'critical' });
    expect((await cfg004.run(c)).passed).toBe(false);
  });

  it('a remote host that is not a container keeps "auto" informational', async () => {
    const fs = markerSnapshot({ config: auto, cgroup: '0::/init.scope\n' });
    const [inst] = await openclawAdapter.detect({ fs });
    expect(inst.gateway?.host).toBe('127.0.0.1');
    const r = await cfg001.run({ installation: inst, configs: inst.configFiles, platform: 'linux', fs });
    expect(r).toMatchObject({ passed: false, severity: 'info' });
    expect(r.evidence?.[0].detail).toContain('no container detected');
  });

  it('NET-001 does not call a configured "auto" gateway unconfigured when the host is unknown', async () => {
    const r = await net001.run(ctxFor(auto, snapshotFs()));
    expect(r.passed).toBe(true);
    expect(r.message).not.toContain('No gateway configured');
    expect(r.message).toContain('CFG-001');
  });

  it('the manifest collects exactly the markers, sentinels as existence only', () => {
    const own = openclawAdapter.getProbeManifest!();
    expect(own.envPresence).toEqual(['FLY_MACHINE_ID', 'FLY_APP_NAME']);
    expect(own.systemPaths).toContain('/proc/1/cgroup');
    const m = buildProbeManifest([openclawAdapter]);
    for (const sentinel of ['/.dockerenv', '/run/.containerenv', '/var/run/.containerenv']) {
      expect(m.metadataGlobPatterns).toContain(sentinel);
      expect([...m.filePaths, ...m.globPatterns, ...m.systemPaths!]).not.toContain(sentinel);
    }
    // presence only, no FLY_ prefix at all (FLY_API_TOKEN is a credential, and
    // a prefix ships FLY_MACHINE_ID_* values)
    expect(m.envPrefixes.filter(p => p.startsWith('FLY'))).toEqual([]);
    expect(m.envPresence).toEqual(['FLY_MACHINE_ID', 'FLY_APP_NAME']);
  });
});

describe('dt20 g4-F4: an unset gateway.bind is "auto" inside a container', () => {
  const unset = { gateway: { mode: 'local', auth: { mode: 'token', token: '${OPENCLAW_GATEWAY_TOKEN}' } } };

  it('resolves to 0.0.0.0 in a container, loopback outside or when unknown', async () => {
    const inside = markerSnapshot({ config: unset, sentinel: '/.dockerenv' });
    const [a] = await openclawAdapter.detect({ fs: inside });
    expect(a.gateway?.host).toBe('0.0.0.0');
    const r = await cfg001.run({ installation: a, configs: a.configFiles, platform: 'linux', fs: inside });
    expect(r).toMatchObject({ passed: false, severity: 'critical' });
    const [b] = await openclawAdapter.detect({ fs: markerSnapshot({ config: unset }) });
    expect(b.gateway?.host).toBe('127.0.0.1');
    expect(openclawAdapter.getGatewayInfo(unset)?.host).toBe('127.0.0.1');
  });

  it('Tailscale serve/funnel keeps an unset bind on loopback (upstream resolves it before the container default)', async () => {
    const ts = { gateway: { ...unset.gateway, tailscale: { mode: 'serve' } } };
    const [inst] = await openclawAdapter.detect({ fs: markerSnapshot({ config: ts, sentinel: '/.dockerenv' }) });
    expect(inst.gateway?.host).toBe('127.0.0.1');
    const off = { gateway: { ...unset.gateway, tailscale: { mode: 'off' } } };
    const [inst2] = await openclawAdapter.detect({ fs: markerSnapshot({ config: off, sentinel: '/.dockerenv' }) });
    expect(inst2.gateway?.host).toBe('0.0.0.0');
  });

  it('OC-008 counts it as reachable beyond the host in a container only', () => {
    expect(openclawGatewayExposed(unset, true)).toBe(true);
    expect(openclawGatewayExposed(unset, false)).toBe(false);
    expect(openclawGatewayExposed(unset, undefined)).toBe(false);
  });
});

describe('OpenClaw gateway port (resolveGatewayPort, 2026.11.2)', () => {
  it('takes OPENCLAW_GATEWAY_PORT, then gateway.port, then 18789', async () => {
    const { openclawGatewayPort } = await import('./openclaw.js');
    expect(openclawGatewayPort(undefined, undefined, undefined)).toBe(18789);
    expect(openclawGatewayPort(19000, undefined, undefined)).toBe(19000);
    expect(openclawGatewayPort(19000, '20001', undefined)).toBe(20001);
    expect(openclawGatewayPort(19000, '127.0.0.1:20002', undefined)).toBe(20002);
    expect(openclawGatewayPort(19000, '[::1]:20003', undefined)).toBe(20003);
    expect(openclawGatewayPort(19000, 'nope', undefined)).toBe(19000);
  });

  it('derives a --profile gateway\'s default port from the profile name', async () => {
    const { openclawGatewayPort } = await import('./openclaw.js');
    const port = openclawGatewayPort(undefined, undefined, 'work');
    expect(port).toBeGreaterThanOrEqual(20000);
    expect(port).toBeLessThan(60000);
    expect(openclawGatewayPort(undefined, undefined, 'default')).toBe(18789);
  });
});
