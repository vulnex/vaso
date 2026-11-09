import { describe, it, expect } from 'vitest';
import type { ScanContext } from '../../core/types.js';
import type { MCPConfig, MCPServerSource } from '../../mcp/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { InMemoryMcpStateStore } from '../../mcp/mcp-state-store.js';
import { maliciousPackage, malwareFromFirstRelease, mcp027, pinnedRunnerPackage, unpinnedSpecAffected } from './mcp-027-vulnerable-version.js';

const server = (command: string, args: string[], name = 's') => ({ name, command, args, transport: 'stdio' as const });

function ctx(configs: MCPConfig[], sources: MCPServerSource[] = [], store = new InMemoryMcpStateStore()): ScanContext {
  return {
    installation: { agent: 'mcp', installDir: '/tmp', configFiles: [] },
    configs: [],
    platform: 'darwin',
    fs: new LocalFSProvider(),
    mcpConfigs: configs,
    mcpServerSources: sources,
    mcpStateStore: store,
  };
}

const run = (command: string, args: string[]) =>
  mcp027.run(ctx([{ source: 'x', filePath: '/tmp/m.json', servers: [server(command, args)] }]));

describe('dt20 g2-F1: MCP-027 reports unpinned specs that can only install an affected release', () => {
  it.each([
    [['-y', 'mcp-server-github'], 'MAL-2026-5479'],
    [['-y', 'mcp-server-github@latest'], 'MAL-2026-5479'],
    [['-y', '@apexacc/audit'], 'MAL-2026-17923'],
    [['-y', '@apexacc/audit@^1.0.0'], 'MAL-2026-17923'],
    [['-y', '@apexacc/audit@next'], 'MAL-2026-17923'],
    // >=1.0.16 with no fix: the latest release is the backdoored line
    [['-y', 'postmark-mcp'], 'VASO-MAL-2025-001'],
    [['-y', 'postmark-mcp@^1.0.16'], 'VASO-MAL-2025-001'],
  ])('npx %j → %s', async (args, id) => {
    const r = await run('npx', args);
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('critical');
    expect(r.evidence?.some((e) => e.detail?.startsWith(`${id}:`))).toBe(true);
  });

  it('a moving tag of a package with malicious releases is reported (decision 1)', async () => {
    // postmark-mcp@next may point at a backdoored >=1.0.16 release
    const r = await run('npx', ['-y', 'postmark-mcp@next']);
    expect(r.evidence?.[0].detail).toContain('postmark-mcp has published malicious releases (>=1.0.16); run as postmark-mcp (moving tag) it can install one — pin a vetted version');
  });

  it('dt20 g3-N3: a range installs its newest release — an unfixed open-ended line inside it is reported', async () => {
    // ^1.0.0 admits clean 1.0.x, but the installer picks the newest: the backdoored >=1.0.16 line
    const r = await run('npx', ['-y', 'postmark-mcp@^1.0.0']);
    expect(r.passed).toBe(false);
    expect(r.evidence?.[0].detail).toContain('installs the newest release it admits');
    // a range ending before the affected line: no affected release to install,
    // but the package has shipped malware — reported as such (decision 1)
    expect((await run('npx', ['-y', 'postmark-mcp@<=1.0.15'])).evidence?.[0].detail).toContain('has published malicious releases');
    expect((await run('npx', ['-y', 'postmark-mcp@1.0.15'])).passed).toBe(true);
    expect(unpinnedSpecAffected({ kind: 'range', range: '>=1.0.0' }, 'npm', '>=1.0.16', undefined)).toBe(true);
    expect(unpinnedSpecAffected({ kind: 'range', range: '<=1.0.16' }, 'npm', '>=1.0.16', undefined)).toBe(true);
    expect(unpinnedSpecAffected({ kind: 'range', range: '<1.0.16' }, 'npm', '>=1.0.16', undefined)).toBe(false);
    // …only without a fix: a fixed release in the range can be what it installs
    expect(unpinnedSpecAffected({ kind: 'range', range: '^1.0.0' }, 'npm', '>=1.0.16', '1.0.20')).toBe(false);
  });

  it('an advisory with a fixed release the spec can resolve to is not reported', async () => {
    // CVE-2025-6514: mcp-remote >=0.0.5 <0.1.16, fixed 0.1.16
    expect((await run('npx', ['-y', 'mcp-remote'])).passed).toBe(true);
    expect((await run('npx', ['-y', 'mcp-remote@^0.1.0'])).passed).toBe(true);
    // …but a range that ends before the fix is entirely affected
    const r = await run('npx', ['-y', 'mcp-remote@>=0.1.0 <0.1.16']);
    expect(r.evidence?.some((e) => e.detail?.startsWith('CVE-2025-6514:'))).toBe(true);
  });

  it('git URLs and direct references are not matched against registry advisories', async () => {
    expect((await run('npx', ['-y', 'github:someone/mcp-server-github'])).passed).toBe(true);
    expect(pinnedRunnerPackage(server('uvx', ['--from', 'mcp-teamviewer @ git+https://example.com/x', 'mcp-teamviewer']))?.resolves).toBeUndefined();
  });

  it('PyPI unpinned spec matches an open-ended malicious advisory only', async () => {
    expect(pinnedRunnerPackage(server('uvx', ['some-mcp']))?.resolves).toEqual({ kind: 'latest' });
    expect(pinnedRunnerPackage(server('uvx', ['some-mcp>=1.0,<2']))?.resolves).toEqual({ kind: 'range', range: '>=1.0,<2' });
    expect(unpinnedSpecAffected({ kind: 'latest' }, 'pypi', '>=0.0.0', undefined)).toBe(true);
    expect(unpinnedSpecAffected({ kind: 'range', range: '~=1.2' }, 'pypi', '>=1.0.0', undefined)).toBe(true);
    // ~=1.2 admits 1.3+ — its newest release is in the unfixed >=1.3.0 line (g3-N3); ~=1.2.0 stops at <1.3.0
    expect(unpinnedSpecAffected({ kind: 'range', range: '~=1.2' }, 'pypi', '>=1.3.0', undefined)).toBe(true);
    expect(unpinnedSpecAffected({ kind: 'range', range: '~=1.2.0' }, 'pypi', '>=1.3.0', undefined)).toBe(false);
  });

  it('unpinned specs record no version history', async () => {
    const store = new InMemoryMcpStateStore();
    await mcp027.run(ctx([{ source: 'x', filePath: '/tmp/m.json', servers: [server('npx', ['-y', 'some-pkg'])] }], [], store));
    expect(await store.load('version-some-pkg')).toBeNull();
  });
});

describe('dt20 g2-F4/F5: MCP-027 shipped-dependency names and info severity', () => {
  const source = (dep: { name: string; version: string; ecosystem: 'npm' | 'pypi' }): MCPServerSource => ({
    serverName: 'local',
    dependencies: [{ ...dep, source: '/tmp/srv/requirements.txt' }],
  });

  it('a normalized PyPI dependency name matches an advisory written with dots', async () => {
    // advisory: awslabs.aws-api-mcp-server >=1.3.0 <1.6.0; dependency parsers normalize names (PEP 503)
    const r = await mcp027.run(ctx([], [source({ name: 'awslabs-aws-api-mcp-server', version: '1.5.0', ecosystem: 'pypi' })]));
    expect(r.evidence?.some((e) => e.detail?.startsWith('CVE-2026-115413:'))).toBe(true);
  });

  it('an info-severity advisory on a pinned server is an info finding', async () => {
    const r = await run('npx', ['-y', '@aborruso/ckan-mcp-server@0.4.111']);
    expect(r.passed).toBe(false);
    expect(r.evidence?.some((e) => e.detail?.startsWith('CVE-2026-76894:'))).toBe(true);
    expect(r.severity).toBe('info');
  });

  it('a rollback still makes it a warning', async () => {
    const store = new InMemoryMcpStateStore();
    const cfg = (v: string): MCPConfig[] => [{ source: 'x', filePath: '/tmp/m.json', servers: [server('npx', ['-y', `@aborruso/ckan-mcp-server@${v}`])] }];
    await mcp027.run(ctx(cfg('0.4.200'), [], store));
    const r = await mcp027.run(ctx(cfg('0.4.111'), [], store));
    expect(r.severity).toBe('warning');
  });
});

describe('dt20 decision 1: a package with a malicious-package advisory is reported whenever it runs unpinned', () => {
  it.each([
    ['uvx', ['mcp-server-github-py-not-listed']],
  ])('control: %s %j without an advisory is clean', async (command, args) => {
    expect((await run(command, args)).passed).toBe(true);
  });

  it.each([
    ['npx', ['-y', 'mcp-server-notion@next']],
    ['npx', ['-y', '@apexacc/audit@*']],
    ['npx', ['-y', '@apexacc/audit@x']],
    ['npx', ['-y', '@apexacc/audit@>=2.0.0']],
  ])('malware outright (>=0.0.0): %s %j', async (command, args) => {
    const r = await run(command, args);
    expect(r.severity).toBe('critical');
    expect(r.evidence?.[0].detail).toContain('installs a package published as malware, so no release of it is safe');
  });

  it.each([
    ['uvx', ['mcp-teamviewer']],
    ['uvx', ['mcp-teamviewer@latest']],
    ['uvx', ['--from', 'mcp-teamviewer', 'x']],
    ['uvx', ['MCP_TeamViewer']],
    ['npx', ['-y', '@dforge-core/dforge-mcp']],
    ['npx', ['-y', '@atlisp/mcp']],
    ['npx', ['-y', '@atlisp/mcp@next']],
    ['npx', ['-y', '@atlisp/mcp@^1.12.0']],
    ['npx', ['-y', 'gemini-computer-use']],
    ['npx', ['-y', '@atom8n/inspector']],
    ['npx', ['-y', 'postmark-mcp@next']],
  ])('specific malicious releases, reachable: %s %j', async (command, args) => {
    const r = await run(command, args);
    expect(r.severity).toBe('critical');
    expect(r.evidence?.[0].detail).toMatch(/has published malicious releases \(.+\); run as .+ it can install one — pin a vetted version/);
  });

  it.each([
    ['npx', ['-y', '@dforge-core/dforge-mcp@^0.2.22'], '>=0.2.20 <0.2.22'],
    ['npx', ['-y', '@dforge-core/dforge-mcp@>=0.2.22 <0.3.0'], '>=0.2.20 <0.2.22'],
    ['npx', ['-y', '@atom8n/inspector@>=0.17.33'], '>=0.17.32 <0.17.33'],
    ['npx', ['-y', 'postmark-mcp@<1.0.16'], '>=1.0.16'],
    ['npx', ['-y', 'gemini-computer-use@^0.5.0'], '=0.1.2 || =0.4.3 || =0.4.5'],
    ['npx', ['-y', '@atlisp/mcp@~1.13.0'], '=1.12.14'],
    ['uvx', ['mcp-teamviewer>=0.0.2'], '=0.0.1'],
  ])('a range clear of every malicious release is an info note: %s %j', async (command, args, range) => {
    const r = await run(command, args);
    expect(r.passed).toBe(false);
    expect(r.severity).toBe('info');
    expect(r.evidence?.[0].detail).toContain(`has published malicious releases (${range}); this spec`);
    expect(r.evidence?.[0].detail).toContain('excludes them — keep it pinned away from them');
    expect(r.evidence?.[0].detail).not.toContain('can install one');
  });

  it('an exact pin outside the malicious releases stays clean', async () => {
    for (const spec of ['@dforge-core/dforge-mcp@0.2.22', '@atlisp/mcp@1.12.13', '@atlisp/mcp@1.12.14-0', 'gemini-computer-use@0.4.4', '@atom8n/inspector@0.17.33']) {
      expect((await run('npx', ['-y', spec])).passed, spec).toBe(true);
    }
    expect((await run('uvx', ['mcp-teamviewer==0.0.2'])).passed).toBe(true);
    expect((await run('uvx', ['mcp-teamviewer==0.0.1'])).passed).toBe(false);
    expect((await run('npx', ['-y', '@atlisp/mcp@1.12.14'])).passed).toBe(false);
  });

  it('a prerelease of an all-releases-malicious package is affected (0.0.0-dev escapes >=0.0.0)', async () => {
    const r = await run('npx', ['-y', 'mcp-server-github@0.0.0-dev']);
    expect(r.severity).toBe('critical');
    expect(r.evidence?.[0].detail).toContain('MAL-2026-5479: mcp-server-github@0.0.0-dev is affected');
  });

  it('a registry tarball URL is matched by the name and version it names', async () => {
    const r = await run('npx', ['-y', 'https://registry.npmjs.org/@apexacc/audit/-/audit-1.0.0.tgz']);
    expect(r.evidence?.[0].detail).toContain('MAL-2026-17923: @apexacc/audit@1.0.0 is affected');
    expect(pinnedRunnerPackage(server('npx', ['-y', 'https://registry.npmjs.org/mcp-remote/-/mcp-remote-0.1.15.tgz']))).toMatchObject({ name: 'mcp-remote', version: '0.1.15' });
  });

  it('git and direct references are not the registry package', async () => {
    expect((await run('uvx', ['--from', 'mcp-teamviewer @ git+https://example.com/x', 'mcp-teamviewer'])).passed).toBe(true);
  });

  it('malwareFromFirstRelease(): every release, from the range itself', () => {
    const adv = (versionConstraint: string, tags = ['mcp', 'malicious-package']) =>
      ({ id: 'x', title: 'x', agent: 'mcp', affectedVersions: versionConstraint, severity: 'critical', description: '', published: '', tags, affectedDependency: { name: 'p', versionConstraint } }) as const;
    expect(malwareFromFirstRelease({ ...adv('>=0.0.0') })).toBe(true);
    expect(malwareFromFirstRelease({ ...adv('>=0.0.1') })).toBe(true);
    expect(malwareFromFirstRelease({ ...adv('*') })).toBe(true);
    expect(malwareFromFirstRelease({ ...adv('=0.0.1') })).toBe(false);
    expect(malwareFromFirstRelease({ ...adv('>=0.9.0') })).toBe(false);
    expect(malwareFromFirstRelease({ ...adv('>=0.0.0 <1.0.0') })).toBe(false);
    expect(malwareFromFirstRelease({ ...adv('>=0.0.0', ['mcp', 'cve']) })).toBe(false);
    expect(maliciousPackage({ ...adv('>=0.2.20 <0.2.22') })).toBe(true);
  });
});

describe('dt20 g3-N1: a range is judged against the advisory upper bound when it names no fix', () => {
  it('@1mcp/agent@^0.30.0 sits inside >=0.20.0 <=0.39.0', async () => {
    const r = await run('npx', ['-y', '@1mcp/agent@^0.30.0']);
    expect(r.evidence?.some((e) => e.detail?.startsWith('CVE-2026-108586:'))).toBe(true);
    expect((await run('npx', ['-y', '@1mcp/agent@^1.0.0'])).passed).toBe(true);
  });
});

describe('dt20 g3 re-verify: a range installs its newest release, also with a fix', () => {
  it.each([
    [['-y', 'mcp-remote@<0.1.16']],
    [['-y', 'mcp-remote@0.1.14 || 0.1.15']],
    [['-y', 'mcp-remote@>=0.1.0 <0.1.16']],
    [['-y', 'mcp-remote@0.1.10 - 0.1.15']],
  ])('npx %j → CVE-2025-6514', async (args) => {
    const r = await run('npx', args);
    expect(r.evidence?.some((e) => e.detail?.startsWith('CVE-2025-6514:'))).toBe(true);
  });

  it('the wording says which release: the newest it admits, or every one', async () => {
    expect((await run('npx', ['-y', 'mcp-remote@<0.1.16'])).evidence?.[0].detail).toContain('mcp-remote@<0.1.16 installs the newest release it admits, which is affected');
    expect((await run('npx', ['-y', 'mcp-remote@0.1.14 || 0.1.15'])).evidence?.[0].detail).toContain('every release');
  });

  it.each([
    [['-y', 'mcp-remote']],
    [['-y', 'mcp-remote@~0.1.10']],
    [['-y', 'mcp-remote@^0.1.0']],
    [['-y', 'mcp-remote@0.1.x']],
    [['-y', 'mcp-remote@0.1.15 || ^0.2.0']],
    [['-y', '@bytebase/dbhub@^0.22.0']],
    [['-y', '@bytebase/dbhub@>=0.22.0']],
  ])('a spec whose newest release has the fix stays clean: %j', async (args) => {
    expect((await run('npx', args)).passed).toBe(true);
  });

  it('|| and hyphen ranges of malicious releases are judged per alternative', async () => {
    expect((await run('npx', ['-y', '@dforge-core/dforge-mcp@0.2.20 || 0.2.21'])).severity).toBe('critical');
    expect((await run('npx', ['-y', '@dforge-core/dforge-mcp@0.2.20 - 0.2.21'])).severity).toBe('critical');
    expect((await run('npx', ['-y', '@dforge-core/dforge-mcp@0.2.19 || 0.2.22'])).severity).toBe('info');
  });
});
