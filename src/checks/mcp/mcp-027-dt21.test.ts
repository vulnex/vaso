import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Platform, ScanContext } from '../../core/types.js';
import type { MCPConfig, MCPServerSource } from '../../mcp/types.js';
import type { ServerDependency } from '../../mcp/server-dependencies.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { InMemoryMcpStateStore } from '../../mcp/mcp-state-store.js';
import { getAdvisoryDatabase, reloadAdvisoryDatabase } from '../../advisory/database.js';
import { declaredRangeMatch, declaredResolution, mcp027, pinnedRunnerPackage } from './mcp-027-vulnerable-version.js';
import { mcp028 } from './mcp-028-config-drift.js';
import { adv002 } from '../advisory/adv-002-dependency-vuln.js';

function ctx(configs: MCPConfig[], sources: MCPServerSource[] = [], platform: Platform = 'darwin', store = new InMemoryMcpStateStore()): ScanContext {
  return {
    installation: { agent: 'mcp', installDir: '/tmp', configFiles: [] },
    configs: [], platform, fs: new LocalFSProvider(),
    mcpConfigs: configs, mcpServerSources: sources, mcpStateStore: store,
  };
}
const npx = (args: string[], name = 's'): MCPConfig => ({ source: 'x', filePath: '/tmp/m.json', servers: [{ name, command: 'npx', args, transport: 'stdio' }] });
const shipping = (dependencies: ServerDependency[]): MCPServerSource => ({ serverName: 'local', localPath: '/srv/index.js', sourceCode: 'x', dependencies });
const declared = (name: string, range: string): ServerDependency => ({ name, ecosystem: 'npm', range, source: '/srv/package.json' });
const ids = (r: { evidence?: Array<{ detail?: string }> }) => (r.evidence ?? []).map((e) => e.detail?.split(':')[0]);

beforeEach(() => reloadAdvisoryDatabase());
afterEach(() => reloadAdvisoryDatabase());

describe('dt21 g2-F3: a malformed tarball URL costs no other server its finding', () => {
  it('skips the bad URL and still reports postmark-mcp@1.0.16', async () => {
    const r = await mcp027.run(ctx([{
      source: 'x', filePath: '/tmp/m.json', servers: [
        { name: 'bad', command: 'npx', args: ['-y', 'https://registry.npmjs.org/foo%E0%A4%A/-/foo-1.0.0.tgz'], transport: 'stdio' },
        { name: 'p', command: 'npx', args: ['-y', 'postmark-mcp@1.0.16'], transport: 'stdio' },
      ],
    }]));
    expect(r.errored).toBeFalsy();
    expect(r.severity).toBe('critical');
    expect(ids(r)).toContain('VASO-MAL-2025-001');
  });
});

describe('dt21 g2-F6: npm aliases and an empty version', () => {
  it.each([
    [['-y', 'pm@npm:postmark-mcp@1.0.16'], 'postmark-mcp', '1.0.16'],
    [['-y', '@x/pm@npm:postmark-mcp@1.0.16'], 'postmark-mcp', '1.0.16'],
    [['-y', '-p', 'postmark@npm:postmark-mcp', 'postmark-mcp'], 'postmark-mcp', undefined],
    [['-y', 'postmark-mcp@'], 'postmark-mcp', undefined],
  ])('npx %j installs %s', async (args, name, version) => {
    const pkg = pinnedRunnerPackage(npx(args).servers[0]);
    expect(pkg?.name).toBe(name);
    expect(pkg?.version).toBe(version);
    const r = await mcp027.run(ctx([npx(args)]));
    expect(ids(r)).toContain('VASO-MAL-2025-001');
    expect(r.severity).toBe('critical');
  });

  it('`pkg@*` reads as "installs the latest release"', async () => {
    const r = await mcp027.run(ctx([npx(['-y', 'postmark-mcp@*'])]));
    expect(r.evidence?.[0].detail).toContain('installs the latest release');
  });
});

describe('dt21 g2-F2: a malicious package declared by range is reported like an unpinned runner spec', () => {
  it.each([
    ['@apexacc/audit', '^1.0.0', 'MAL-2026-17923'],
    ['mcp-server-github', '*', 'MAL-2026-5479'],
    ['mcp-server-github', 'latest', 'MAL-2026-5479'],
    ['postmark-mcp', '^1.0.0', 'VASO-MAL-2025-001'],
    ['gemini-computer-use', '^0.4.0', 'MAL-2026-16355'],
  ])('MCP-027: %s %s → %s', async (name, range, id) => {
    const r = await mcp027.run(ctx([], [shipping([declared(name, range)])]));
    expect(ids(r)).toContain(id);
    expect(r.severity).toBe('critical');
  });

  it('a range clear of every malicious release is noted, not live', async () => {
    const r = await mcp027.run(ctx([], [shipping([declared('gemini-computer-use', '>=0.4.6 <0.5')])]));
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
    expect(r.evidence?.[0].detail).toContain('which this range excludes');
  });

  it('git, file and alias specs install nothing the registry advisories describe', () => {
    for (const spec of ['github:x/postmark-mcp', 'file:../postmark-mcp', 'npm:postmark-mcp@1.0.16', 'https://example.com/x.tgz']) {
      expect(declaredResolution(spec, 'npm')).toBeUndefined();
    }
    expect(declaredResolution('', 'pypi')).toEqual({ kind: 'latest' });
    expect(declaredResolution('next', 'npm')).toEqual({ kind: 'tag' });
  });

  it('a non-malicious advisory keeps the fix-aware rule (a range that can install the fix is fine)', () => {
    const adv = getAdvisoryDatabase().advisories.find((a) => a.id === 'CVE-2025-6514')!;
    expect(declaredRangeMatch('^0.1.0', 'npm', adv)).toBeUndefined();
    expect(declaredRangeMatch('<0.1.16', 'npm', adv)).toBe('affected');
  });

  it('ADV-002 reads a declared range the same way', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vaso-dt21-adv002-'));
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { '@apexacc/audit': '^1.0.0', 'mcp-server-github': '*', lodash: '^4.17.0' } }));
      const r = await adv002.run({ installation: { agent: 'nanoclaw', installDir: dir, configFiles: [] }, configs: [], platform: 'darwin', fs: new LocalFSProvider() });
      expect(r.passed).toBe(false);
      expect(r.severity).toBe('critical');
      expect(r.evidence?.map((e) => e.detail?.split(':')[0]).sort()).toEqual(['MAL-2026-17923', 'MAL-2026-5479']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('dt21 g2-F7: OSV results respect a bundled advisory\'s platform tags', () => {
  it('an OSV twin of a Windows-only bundled advisory is not reported on macOS', async () => {
    getAdvisoryDatabase().advisories.push({
      id: 'TEST-WIN-DEP', title: 'Windows-only flaw', agent: 'mcp', affectedVersions: '*', severity: 'critical',
      description: 'test', published: '2026-11-01', platforms: ['win32'],
      reference: 'https://github.com/advisories/GHSA-test-win0-dep0',
      affectedDependency: { name: 'some-lib', versionConstraint: '<2.0.0', ecosystem: 'npm' },
    });
    const dep: ServerDependency = {
      name: 'some-lib', ecosystem: 'npm', version: '1.0.0', source: '/srv/package-lock.json',
      vulnerabilities: [{ id: 'CVE-2026-0001', aliases: ['GHSA-test-win0-dep0'], summary: 'Windows-only flaw', severity: 'critical', reference: 'https://osv.dev/vulnerability/GHSA-test-win0-dep0' }],
    };
    const mac = await mcp027.run(ctx([], [shipping([dep])], 'darwin'));
    expect(mac.passed).toBe(true);
    const win = await mcp027.run(ctx([], [shipping([{ ...dep }])], 'win32'));
    expect(ids(win)).toEqual(['TEST-WIN-DEP']);
  });
});

describe('dt21 g3-F13: a --source-only scan starts no drift baseline', () => {
  it('no config scanned → nothing saved; the next scan establishes the baseline instead of reporting every server as new', async () => {
    const store = new InMemoryMcpStateStore();
    await mcp028.run(ctx([], [shipping([])], 'darwin', store));
    const next = await mcp028.run(ctx([npx(['-y', 'postmark-mcp@1.0.15'])], [], 'darwin', store));
    expect(next.passed).toBe(true);
    expect(next.message).toContain('baseline established');
  });
});
