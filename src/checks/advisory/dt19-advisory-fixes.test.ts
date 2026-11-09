import { describe, it, expect, beforeEach, afterEach, beforeAll, vi } from 'vitest';
import { generateKeyPairSync, sign, createPrivateKey } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AgentInstallation, Platform, ScanContext } from '../../core/types.js';
import type { Advisory } from '../../advisory/advisory-types.js';
import type { MCPConfig } from '../../mcp/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { satisfies, compareVersions, parseSemVer } from '../../core/semver.js';
import { getAdvisoryDatabase, reloadAdvisoryDatabase } from '../../advisory/database.js';
import { adv001 } from './adv-001-version-vuln.js';
import { adv004 } from './adv-004-known-exploit.js';
import { mcp027, pinnedRunnerPackage } from '../mcp/mcp-027-vulnerable-version.js';
import { mcp028 } from '../mcp/mcp-028-config-drift.js';
import { InMemoryMcpStateStore } from '../../mcp/mcp-state-store.js';
import { fetchAndUpdateFeed, isFeedStale, loadCachedFeed } from '../../ioc/updater.js';
import { cachedAdvisoryFeedVersion, fetchAndUpdateAdvisoryFeed, isAdvisoryFeedStale } from '../../advisory/updater.js';
import { BUNDLED_ADVISORY_FEED_VERSION } from '../../advisory/database.js';

function agentContext(installation: Partial<AgentInstallation>, platform: Platform = 'darwin'): ScanContext {
  const inst: AgentInstallation = { agent: 'openclaw', installDir: '/tmp/test', configFiles: [], ...installation };
  return { installation: inst, configs: [], platform, fs: new LocalFSProvider() };
}

function mcpContext(configs: MCPConfig[], store = new InMemoryMcpStateStore(), platform: Platform = 'darwin'): ScanContext {
  return {
    installation: { agent: 'mcp', installDir: '/tmp', configFiles: [] },
    configs: [],
    platform,
    fs: new LocalFSProvider(),
    mcpConfigs: configs,
    mcpStateStore: store,
  };
}

const advisory = (a: Partial<Advisory> & Pick<Advisory, 'id' | 'agent' | 'affectedVersions'>): Advisory => ({
  title: 'Test advisory',
  severity: 'critical',
  description: 'test',
  published: '2026-11-01',
  tags: ['framework', 'cve'],
  ...a,
});

describe('g2-F2: OpenClaw correction releases', () => {
  it('correctionSuffix sorts 2026.7.1-1 after its base and before the next release', () => {
    const opts = { correctionSuffix: true };
    expect(satisfies('2026.7.1-1', '<2026.7.1', opts)).toBe(false);
    expect(satisfies('2026.2.6-1', '>=2026.2.6', opts)).toBe(true);
    expect(satisfies('2026.7.1-2', '>2026.7.1-1 <2026.7.2', opts)).toBe(true);
    // A real prerelease keeps its meaning
    expect(satisfies('2026.7.1-beta.6', '<2026.7.1', opts)).toBe(true);
    expect(parseSemVer('2026.7.1-1', opts)).toMatchObject({ prerelease: undefined, correction: 1 });
  });

  it('plain semver is unchanged without the option', () => {
    expect(satisfies('1.0.0-1', '<1.0.0')).toBe(true);
    expect(compareVersions('1.0.0-1', '1.0.0')).toBe(-1);
  });

  describe('ADV-001 / ADV-004', () => {
    beforeEach(() => {
      reloadAdvisoryDatabase();
      getAdvisoryDatabase().advisories.push(
        advisory({ id: 'TEST-OC-OLD', agent: 'openclaw', affectedVersions: '<2026.7.1', fixedVersion: '2026.7.1', exploitAvailable: true }),
        advisory({ id: 'TEST-OC-NEW', agent: 'openclaw', affectedVersions: '>=2026.2.6 <2026.2.7', exploitAvailable: true }),
      );
    });
    afterEach(() => reloadAdvisoryDatabase());

    const ids = (r: { evidence?: { detail?: string }[] }) => (r.evidence ?? []).map(e => e.detail!.split(':')[0]);

    it('a correction release is not affected by an advisory fixed in its base', async () => {
      expect(ids(await adv001.run(agentContext({ version: '2026.7.1-1' })))).not.toContain('TEST-OC-OLD');
      expect(ids(await adv004.run(agentContext({ version: '2026.7.1-1' })))).not.toContain('TEST-OC-OLD');
    });

    it('a correction release is affected by an advisory from its base on', async () => {
      expect(ids(await adv001.run(agentContext({ version: '2026.2.6-1' })))).toContain('TEST-OC-NEW');
    });

    it('other agents keep semver prerelease semantics', async () => {
      getAdvisoryDatabase().advisories.push(advisory({ id: 'TEST-HM', agent: 'hermes', affectedVersions: '<1.0.0' }));
      expect(ids(await adv001.run(agentContext({ agent: 'hermes', version: '1.0.0-1' })))).toContain('TEST-HM');
    });
  });
});

describe('g2-F5: platform-limited advisories', () => {
  beforeEach(() => {
    reloadAdvisoryDatabase();
    getAdvisoryDatabase().advisories.push(
      advisory({ id: 'TEST-WIN', agent: 'opencode', affectedVersions: '<2.0.0', exploitAvailable: true, tags: ['coding-agent', 'cve'], platforms: ['win32'] }),
      advisory({
        id: 'TEST-WIN-PKG', agent: 'mcp', affectedVersions: '>=0.0.0', tags: ['mcp'], platforms: ['win32'],
        affectedDependency: { name: 'test-win-only-mcp', versionConstraint: '<2.0.0' },
      }),
    );
  });
  afterEach(() => reloadAdvisoryDatabase());

  it('ADV-001 / ADV-004 skip a Windows-only advisory on macOS and Linux', async () => {
    for (const platform of ['darwin', 'linux'] as const) {
      const ctx = agentContext({ agent: 'opencode', version: '1.0.0' }, platform);
      expect((await adv001.run(ctx)).evidence?.some(e => e.detail?.startsWith('TEST-WIN'))).toBeFalsy();
      expect((await adv004.run(ctx)).evidence?.some(e => e.detail?.startsWith('TEST-WIN'))).toBeFalsy();
    }
  });

  it('ADV-001 / ADV-004 report it on Windows', async () => {
    const ctx = agentContext({ agent: 'opencode', version: '1.0.0' }, 'win32');
    expect((await adv001.run(ctx)).evidence?.some(e => e.detail?.startsWith('TEST-WIN'))).toBe(true);
    expect((await adv004.run(ctx)).evidence?.some(e => e.detail?.startsWith('TEST-WIN'))).toBe(true);
  });

  it('MCP-027 honours the platform', async () => {
    const cfg: MCPConfig[] = [{ source: 'x', filePath: '/tmp/m.json', servers: [{ name: 's', command: 'npx', args: ['-y', 'test-win-only-mcp@1.0.0'], transport: 'stdio' }] }];
    expect((await mcp027.run(mcpContext(cfg, undefined, 'darwin'))).passed).toBe(true);
    expect((await mcp027.run(mcpContext(cfg, undefined, 'win32'))).passed).toBe(false);
  });
});

describe('g2-F4: MCP-027 reads every package runner', () => {
  const server = (command: string, args: string[]) => ({ name: 's', command, args, transport: 'stdio' as const });

  it.each([
    ['bunx', ['mcp-remote@0.1.15']],
    ['pnpm', ['dlx', 'mcp-remote@0.1.15']],
    ['npm', ['exec', '--yes', 'mcp-remote@0.1.15']],
    ['npx', ['--package=mcp-remote@0.1.15', 'mcp-remote']],
    ['npx', ['--registry', 'https://registry.example.com', 'mcp-remote@0.1.15']],
  ])('%s %j', async (command, args) => {
    expect(pinnedRunnerPackage(server(command, args))).toEqual({ name: 'mcp-remote', ecosystem: 'npm', version: '0.1.15' });
    const r = await mcp027.run(mcpContext([{ source: 'x', filePath: '/tmp/m.json', servers: [server(command, args)] }]));
    expect(r.evidence?.some(e => e.detail?.startsWith('CVE-2025-6514'))).toBe(true);
  });

  it.each([
    ['uvx', ['mcp-contextforge-gateway==1.0.0']],
    ['uvx', ['--from', 'mcp-contextforge-gateway==1.0.0', 'mcpgateway']],
    ['pipx', ['run', 'mcp-contextforge-gateway==1.0.0']],
    ['uvx', ['Awslabs.AWS_API_MCP_Server@1.4.0']],
  ])('PyPI: %s %j', async (command, args) => {
    const r = await mcp027.run(mcpContext([{ source: 'x', filePath: '/tmp/m.json', servers: [server(command, args)] }]));
    expect(r.passed).toBe(false);
  });

  it('a PyPI pin does not match an npm advisory of the same name', async () => {
    const r = await mcp027.run(mcpContext([{ source: 'x', filePath: '/tmp/m.json', servers: [server('uvx', ['mcp-remote==0.1.15'])] }]));
    expect(r.passed).toBe(true);
  });

  it('a PyPI rollback is tracked', async () => {
    const store = new InMemoryMcpStateStore();
    const cfg = (v: string): MCPConfig[] => [{ source: 'x', filePath: '/tmp/m.json', servers: [server('uvx', [`some-mcp==${v}`])] }];
    await mcp027.run(mcpContext(cfg('2.0.0'), store));
    const r = await mcp027.run(mcpContext(cfg('1.5.0'), store));
    expect(r.evidence?.some(e => e.detail?.includes('rolled back from 2.0.0 to 1.5.0'))).toBe(true);
  });
});

describe('g3-F4/F5: MCP-028 pins and baseline keys', () => {
  const cfg = (source: string, args: string[], name = 's'): MCPConfig[] => [
    { source, filePath: '/tmp/dt19/mcp.json', servers: [{ name, command: args[0], args: args.slice(1), transport: 'stdio' }] },
  ];

  it.each([
    [['uvx', 'pkg==1.0.0'], ['uvx', 'pkg']],
    [['pnpm', 'dlx', 'pkg@1.0.0'], ['pnpm', 'dlx', 'pkg']],
    [['uvx', '--from', 'pkg==1.0.0', 'cmd'], ['uvx', '--from', 'pkg', 'cmd']],
  ])('sees a lost pin: %j → %j', async (before, after) => {
    const store = new InMemoryMcpStateStore();
    await mcp028.run(mcpContext(cfg('Cursor', before), store));
    const r = await mcp028.run(mcpContext(cfg('Cursor', after), store));
    expect(r.evidence?.map(e => e.detail)).toEqual([expect.stringContaining('lost its version pin')]);
  });

  it('a range is not a pin', async () => {
    const store = new InMemoryMcpStateStore();
    await mcp028.run(mcpContext(cfg('Cursor', ['npx', 'pkg@1.0.0']), store));
    const r = await mcp028.run(mcpContext(cfg('Cursor', ['npx', 'pkg@^1.0.0']), store));
    expect(r.passed).toBe(false);
  });

  it('the same file scanned with -p ("Custom") is not new', async () => {
    const store = new InMemoryMcpStateStore();
    await mcp028.run(mcpContext(cfg('Claude Desktop', ['npx', 'pkg@1.0.0']), store));
    const r = await mcp028.run(mcpContext(cfg('Custom', ['npx', 'pkg@1.0.0']), store));
    expect(r.passed).toBe(true);
  });

  it('reads an existing source-keyed baseline', async () => {
    const store = new InMemoryMcpStateStore();
    await store.save('config-drift', { 'Cursor::s': { transport: 'stdio', pinned: true, scheme: 'none', hasAuth: false } });
    const same = await mcp028.run(mcpContext(cfg('Cursor', ['npx', 'pkg@1.0.0']), store));
    expect(same.passed).toBe(true);
    expect(same.message).not.toContain('baseline established');
    const store2 = new InMemoryMcpStateStore();
    await store2.save('config-drift', { 'Cursor::s': { transport: 'stdio', pinned: true, scheme: 'none', hasAuth: false } });
    const lost = await mcp028.run(mcpContext(cfg('Cursor', ['npx', 'pkg']), store2));
    expect(lost.evidence?.[0].detail).toContain('lost its version pin');
  });

  it('a regression stays reported until it is undone', async () => {
    const store = new InMemoryMcpStateStore();
    await mcp028.run(mcpContext(cfg('Cursor', ['npx', 'pkg@1.0.0']), store));
    expect((await mcp028.run(mcpContext(cfg('Cursor', ['npx', 'pkg']), store))).passed).toBe(false);
    expect((await mcp028.run(mcpContext(cfg('Cursor', ['npx', 'pkg']), store))).passed).toBe(false);
    expect((await mcp028.run(mcpContext(cfg('Cursor', ['npx', 'pkg@1.0.1']), store))).passed).toBe(true);
  });

  it('per-project servers in one ~/.claude.json stay apart', async () => {
    const store = new InMemoryMcpStateStore();
    const both = (aPinned: boolean): MCPConfig[] => [
      { source: 'Claude Code (project /a)', filePath: '/tmp/dt19/.claude.json', servers: [{ name: 's', command: 'npx', args: [aPinned ? 'pkg@1.0.0' : 'pkg'], transport: 'stdio' }] },
      { source: 'Claude Code (project /b)', filePath: '/tmp/dt19/.claude.json', servers: [{ name: 's', command: 'npx', args: ['pkg@1.0.0'], transport: 'stdio' }] },
    ];
    await mcp028.run(mcpContext(both(true), store));
    const r = await mcp028.run(mcpContext(both(false), store));
    expect(r.evidence?.length).toBe(1);
    expect(r.evidence?.[0].snippet).toContain('project /a');
  });
});

// ── Feed updates (g2-F3, g8-F7) ─────────────────────────────────────

let publicKeyPem: string;
let privateKeyPem: string;
beforeAll(() => {
  const pair = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  publicKeyPem = pair.publicKey;
  privateKeyPem = pair.privateKey;
});

function serve(feed: unknown): void {
  const body = Buffer.from(JSON.stringify(feed));
  const sig = Buffer.from(sign(null, body, createPrivateKey(privateKeyPem)).toString('base64'));
  vi.stubGlobal('fetch', vi.fn().mockImplementation((url: string) => {
    const b = url.endsWith('.sig') ? sig : body;
    return Promise.resolve({ ok: true, arrayBuffer: () => Promise.resolve(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength)) });
  }));
}

const iocFeed = (version: number) => ({ meta: { version, timestamp: '2026-11-01T00:00:00Z', description: 'ioc' }, data: { c2Ips: ['198.51.100.7'] } });
const advFeed = (version: number) => ({
  meta: { version, timestamp: '2026-11-01T00:00:00Z', description: 'adv' },
  data: { advisories: [advisory({ id: 'TEST-FEED', agent: 'openclaw', affectedVersions: '<1.0.0' })] },
});

describe('feed updates', () => {
  let dir: string;
  beforeEach(async () => { dir = await mkdtemp(join(tmpdir(), 'vaso-dt19-feed-')); });
  afterEach(async () => {
    vi.unstubAllGlobals();
    await rm(dir, { recursive: true, force: true });
  });

  it('g2-F3: an IOC check that finds nothing newer clears the stale warning', async () => {
    serve(iocFeed(3));
    expect((await fetchAndUpdateFeed({ feedUrl: 'https://e.test/f.json', feedDir: dir, publicKeyPem })).success).toBe(true);
    const meta = JSON.parse(await readFile(join(dir, 'metadata.json'), 'utf-8'));
    await writeFile(join(dir, 'metadata.json'), JSON.stringify({ ...meta, lastCheckAt: new Date(0).toISOString() }));
    expect(isFeedStale(7, dir)).toBe(true);
    const r = await fetchAndUpdateFeed({ feedUrl: 'https://e.test/f.json', feedDir: dir, publicKeyPem });
    expect(r.message).toContain('not newer');
    expect(isFeedStale(7, dir)).toBe(false);
    expect(JSON.parse(await readFile(join(dir, 'metadata.json'), 'utf-8')).feedVersion).toBe(3);
  });

  it('g2-F3: an advisory check that finds nothing newer clears the stale warning', async () => {
    serve(advFeed(4));
    await fetchAndUpdateAdvisoryFeed({ feedUrl: 'https://e.test/a.json', feedDir: dir, publicKeyPem });
    const meta = JSON.parse(await readFile(join(dir, 'metadata.json'), 'utf-8'));
    await writeFile(join(dir, 'metadata.json'), JSON.stringify({ ...meta, lastCheckAt: new Date(0).toISOString() }));
    expect(isAdvisoryFeedStale(7, dir)).toBe(true);
    const r = await fetchAndUpdateAdvisoryFeed({ feedUrl: 'https://e.test/a.json', feedDir: dir, publicKeyPem });
    expect(r.message).toContain('not newer');
    expect(isAdvisoryFeedStale(7, dir)).toBe(false);
  });

  it('g8-F7: the advisory feed is not installed as the IOC feed', async () => {
    serve(advFeed(99));
    const r = await fetchAndUpdateFeed({ feedUrl: 'https://e.test/advisory-feed.json', feedDir: dir, publicKeyPem });
    expect(r.success).toBe(false);
    expect(r.message).toContain('Not an IOC feed');
    await expect(readFile(join(dir, 'feed.json'))).rejects.toThrow();
  });

  it('g8-F7: the IOC feed is not installed as the advisory feed', async () => {
    serve(iocFeed(99));
    const r = await fetchAndUpdateAdvisoryFeed({ feedUrl: 'https://e.test/feed.json', feedDir: dir, publicKeyPem });
    expect(r.success).toBe(false);
    expect(r.message).toContain('Not an advisory feed');
  });

  it('g8-F7: an advisory feed already cached as the IOC feed is ignored and replaced', async () => {
    const body = Buffer.from(JSON.stringify(advFeed(99)));
    await writeFile(join(dir, 'feed.json'), body);
    await writeFile(join(dir, 'feed.json.sig'), sign(null, body, createPrivateKey(privateKeyPem)).toString('base64'));
    await writeFile(join(dir, 'metadata.json'), JSON.stringify({ lastUpdated: 'x', feedVersion: 99, feedUrl: 'x', lastCheckAt: new Date().toISOString() }));
    expect(await loadCachedFeed(dir, publicKeyPem)).toBeNull();
    // A cache that isn't usable doesn't block the real feed (it is re-fetched despite fresh metadata)
    serve(iocFeed(99));
    const r = await fetchAndUpdateFeed({ feedUrl: 'https://e.test/f.json', feedDir: dir, publicKeyPem });
    expect(r.message).toContain('updated');
    expect(await loadCachedFeed(dir, publicKeyPem)).toEqual(iocFeed(99).data);
  });

  it('g8-F7: a cached advisory feed with a higher version does not refuse the real IOC feed', async () => {
    const body = Buffer.from(JSON.stringify(advFeed(11)));
    await writeFile(join(dir, 'feed.json'), body);
    await writeFile(join(dir, 'feed.json.sig'), sign(null, body, createPrivateKey(privateKeyPem)).toString('base64'));
    await writeFile(join(dir, 'metadata.json'), JSON.stringify({ lastUpdated: 'x', feedVersion: 11, feedUrl: 'x', lastCheckAt: new Date().toISOString() }));
    serve(iocFeed(7));
    const r = await fetchAndUpdateFeed({ feedUrl: 'https://e.test/f.json', feedDir: dir, publicKeyPem });
    expect(r.message).toContain('updated');
    expect(JSON.parse(await readFile(join(dir, 'metadata.json'), 'utf-8')).feedVersion).toBe(7);
  });

  it('g8-F7: a cached IOC feed with a higher version does not refuse the real advisory feed', async () => {
    const body = Buffer.from(JSON.stringify(iocFeed(12)));
    await writeFile(join(dir, 'advisory-feed.json'), body);
    await writeFile(join(dir, 'advisory-feed.json.sig'), sign(null, body, createPrivateKey(privateKeyPem)).toString('base64'));
    await writeFile(join(dir, 'metadata.json'), JSON.stringify({ lastUpdated: 'x', feedVersion: 12, feedUrl: 'x', lastCheckAt: new Date().toISOString() }));
    serve(advFeed(11));
    const r = await fetchAndUpdateAdvisoryFeed({ feedUrl: 'https://e.test/a.json', feedDir: dir, publicKeyPem });
    expect(r.success).toBe(true);
    expect(JSON.parse(await readFile(join(dir, 'metadata.json'), 'utf-8')).feedVersion).toBe(11);
  });

  it('a cached advisory feed older than the bundle is not merged over it', async () => {
    expect(await cachedAdvisoryFeedVersion(dir)).toBe(0);
    serve(advFeed(BUNDLED_ADVISORY_FEED_VERSION - 1));
    await fetchAndUpdateAdvisoryFeed({ feedUrl: 'https://e.test/a.json', feedDir: dir, publicKeyPem });
    // initAdvisoryDatabase merges only a cached feed newer than the bundle
    expect(await cachedAdvisoryFeedVersion(dir)).toBeLessThanOrEqual(BUNDLED_ADVISORY_FEED_VERSION);
  });

  it('g2-F3: an older mirror does not clear the stale warning', async () => {
    serve(iocFeed(5));
    await fetchAndUpdateFeed({ feedUrl: 'https://e.test/f.json', feedDir: dir, publicKeyPem });
    const meta = JSON.parse(await readFile(join(dir, 'metadata.json'), 'utf-8'));
    await writeFile(join(dir, 'metadata.json'), JSON.stringify({ ...meta, lastCheckAt: new Date(0).toISOString() }));
    serve(iocFeed(4));
    const r = await fetchAndUpdateFeed({ feedUrl: 'https://e.test/f.json', feedDir: dir, publicKeyPem });
    expect(r.message).toContain('not newer');
    expect(isFeedStale(7, dir)).toBe(true);
  });
});
