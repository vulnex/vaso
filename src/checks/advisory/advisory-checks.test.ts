import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ScanContext, AgentInstallation, ParsedConfig } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { adv001 } from './adv-001-version-vuln.js';
import { adv002 } from './adv-002-dependency-vuln.js';
import { adv003 } from './adv-003-eol-version.js';
import { adv004 } from './adv-004-known-exploit.js';
import { adv005 } from './adv-005-config-advisory.js';
import { getAdvisoryDatabase, reloadAdvisoryDatabase } from '../../advisory/database.js';

function makeContext(overrides: Partial<AgentInstallation> = {}, configs?: ParsedConfig[]): ScanContext {
  const installation: AgentInstallation = {
    agent: 'openclaw',
    installDir: '/tmp/test',
    configFiles: configs ?? [],
    version: '1.4.0',
    ...overrides,
  };
  return {
    installation,
    configs: configs ?? installation.configFiles,
    platform: 'darwin',
    fs: new LocalFSProvider(),
  };
}

function makeConfig(data: Record<string, unknown> = {}, filePath = '/tmp/test/config.json'): ParsedConfig {
  return {
    raw: JSON.stringify(data),
    format: 'json',
    filePath,
    data,
  };
}

describe('ADV-001: Known Framework Vulnerability', () => {
  beforeEach(() => reloadAdvisoryDatabase());

  it('detects known vulnerability for affected version', async () => {
    // OpenClaw 2026.3.20 is below CVE-2026-35641's 2026.3.24 fix
    const ctx = makeContext({ agent: 'openclaw', version: '2026.3.20' });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.message).toMatch(/^(?:1 known vulnerability affects|\d+ known vulnerabilities affect) /);
    expect(result.evidence?.length).toBeGreaterThan(0);
    expect(result.evidence?.some(e => e.detail?.includes('CVE-2026-35641'))).toBe(true);
  });

  it('passes for fixed version', async () => {
    // 2026.8.1 is the fixed version of the newest bundled OpenClaw advisories
    // (CVE-2026-100552, GHSA-ghpx-6xwq-2w4w, GHSA-5mrc-77hj-xjxv) and clears
    // every earlier calver range.
    const ctx = makeContext({ agent: 'openclaw', version: '2026.8.1' });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('flags a current-era calver version below the real CVE fixes', async () => {
    // 2026.3.13 (a real in-the-wild version) is below CVE-2026-35641's 2026.3.24 fix
    const ctx = makeContext({ agent: 'openclaw', version: '2026.3.13' });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.evidence?.some(e => e.detail?.includes('CVE-2026-35641'))).toBe(true);
  });

  it('reports at the matched advisory severity', async () => {
    // VASO-LYRIE-2026-001 is a warning-level advisory
    const result = await adv001.run(makeContext({ agent: 'lyrie', version: '3.4.0' }));
    expect(result.passed).toBe(false);
    expect(result.severity).toBe('warning');
    // OpenClaw 2026.3.13 matches critical advisories
    expect((await adv001.run(makeContext({ agent: 'openclaw', version: '2026.3.13' }))).severity).toBe('critical');
  });

  it('passes when version not detected', async () => {
    const ctx = makeContext({ agent: 'openclaw', version: undefined });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(true);
    expect(result.message).toContain('not detected');
  });

  it('detects vulnerabilities for other agents', async () => {
    // Gemini CLI 0.39.0 is below CVE-2026-12537's 0.39.1 fix
    const ctx = makeContext({ agent: 'gemini-cli', version: '0.39.0' });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.evidence?.some(e => e.detail?.includes('CVE-2026-12537'))).toBe(true);
  });

  it('passes for unaffected agent', async () => {
    // NanoClaw 3.0.0 should not be affected
    const ctx = makeContext({ agent: 'nanoclaw', version: '3.0.0' });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('flags a coding agent below the GhostApproval fix (Cursor CVE-2026-50549)', async () => {
    const ctx = makeContext({ agent: 'cursor-cli', version: '2.9.0' });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.evidence?.some(e => e.detail?.includes('CVE-2026-50549'))).toBe(true);
  });

  it('clears the GhostApproval advisory at its fix version', async () => {
    const ctx = makeContext({ agent: 'cursor-cli', version: '3.0.0' });
    const result = await adv001.run(ctx);
    expect(result.evidence?.some(e => e.detail?.includes('CVE-2026-50549'))).toBe(false);
    // 3.0.0 is still below CVE-2026-73217's 3.1.2 fix; 3.1.2 clears both.
    expect(result.evidence?.some(e => e.detail?.includes('CVE-2026-73217'))).toBe(true);
    expect((await adv001.run(makeContext({ agent: 'cursor-cli', version: '3.1.2' }))).passed).toBe(true);
  });

  // Feed v7 advisories ship in the bundle: an offline install flags them.
  it.each([
    ['codex', '0.20.0', 'CVE-2025-59532', '0.39.0'],
    ['nemoclaw', '0.0.16', 'CVE-2026-65090', '0.0.25'],
    ['claude-code', '2.1.70', 'CVE-2026-40068', '2.1.260'],
    ['hermes', '0.10.0', 'CVE-2026-9368', '0.16.0'],
    ['openclaw', '2026.4.20', 'CVE-2026-45004', '2026.8.1'],
  ] as const)('flags %s %s offline (%s), clears %s', async (agent, version, id, fixed) => {
    const result = await adv001.run(makeContext({ agent, version }));
    expect(result.passed).toBe(false);
    expect(result.evidence?.some(e => e.detail?.includes(id))).toBe(true);
    const cleared = await adv001.run(makeContext({ agent, version: fixed }));
    expect(cleared.evidence?.some(e => e.detail?.includes(id)) ?? false).toBe(false);
  });

  it('flags Claude Code below the symlink-warning hardening (v2.1.32)', async () => {
    const ctx = makeContext({ agent: 'claude-code', version: '2.1.30' });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.evidence?.some(e => e.detail?.includes('VASO-GHOSTAPPROVAL-CC'))).toBe(true);
  });
});

describe('ADV-002: Dependency Vulnerability', () => {
  beforeEach(() => reloadAdvisoryDatabase());

  it('passes when no package.json or Cargo.toml exists', async () => {
    const ctx = makeContext({ installDir: '/nonexistent' });
    const result = await adv002.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('does not match a PyPI advisory against an npm package of the same name', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vaso-adv002-'));
    try {
      // The Python SDK is `mcp` on PyPI; an npm dependency called `mcp` is another package.
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { mcp: '1.0.0' } }));
      const result = await adv002.run(makeContext({ installDir: dir }));
      expect(result.passed).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('judges ranges like MCP-027 and prefers the installed copy', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vaso-adv002-'));
    try {
      // every version ~0.0.9 admits is affected (>=0.0.5 <0.1.16)
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { 'mcp-remote': '~0.0.9' } }));
      expect((await adv002.run(makeContext({ installDir: dir }))).passed).toBe(false);
      // ^0.1.0 admits fixed releases — not judged from the range alone
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { 'mcp-remote': '^0.1.0' } }));
      expect((await adv002.run(makeContext({ installDir: dir }))).passed).toBe(true);
      // …but the installed copy is what runs
      mkdirSync(join(dir, 'node_modules', 'mcp-remote'), { recursive: true });
      writeFileSync(join(dir, 'node_modules', 'mcp-remote', 'package.json'), JSON.stringify({ name: 'mcp-remote', version: '0.1.10' }));
      const r = await adv002.run(makeContext({ installDir: dir }));
      expect(r.passed).toBe(false);
      expect(r.evidence?.[0].detail).toContain('mcp-remote@0.1.10');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('flags a feed-v7 package advisory offline (bundled) and clears its fix', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vaso-adv002-'));
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { '@bytebase/dbhub': '0.22.4' } }));
      const r = await adv002.run(makeContext({ installDir: dir }));
      expect(r.passed).toBe(false);
      expect(r.evidence?.some(e => e.detail?.includes('CVE-2026-61742'))).toBe(true);
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { '@bytebase/dbhub': '0.22.6' } }));
      expect((await adv002.run(makeContext({ installDir: dir }))).passed).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('finds an undeclared (transitive) vulnerable package installed or locked', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vaso-adv002-'));
    try {
      writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { express: '^4.18.0' } }));
      expect((await adv002.run(makeContext({ installDir: dir }))).passed).toBe(true);
      // MCP Inspector < 0.14.1 (CVE-2025-49596) pulled in by another package
      mkdirSync(join(dir, 'node_modules', '@modelcontextprotocol', 'inspector'), { recursive: true });
      writeFileSync(join(dir, 'node_modules', '@modelcontextprotocol', 'inspector', 'package.json'), JSON.stringify({ version: '0.10.0' }));
      const installed = await adv002.run(makeContext({ installDir: dir }));
      expect(installed.evidence?.some(e => e.detail?.includes('@modelcontextprotocol/inspector@0.10.0'))).toBe(true);
      // Only in the lockfile (nested copy)
      rmSync(join(dir, 'node_modules'), { recursive: true, force: true });
      writeFileSync(join(dir, 'package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: {
        '': { name: 'x' }, 'node_modules/some-dep/node_modules/mcp-remote': { version: '0.1.10' },
      } }));
      const locked = await adv002.run(makeContext({ installDir: dir }));
      expect(locked.evidence?.some(e => e.detail?.includes('mcp-remote@0.1.10'))).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('has correct metadata', () => {
    expect(adv002.id).toBe('ADV-002');
    expect(adv002.category).toBe('advisory');
    expect(adv002.severity).toBe('warning');
  });
});

describe('ADV-003: End-of-Life Version', () => {
  beforeEach(() => reloadAdvisoryDatabase());

  it('detects an end-of-life version from an EOL notice', async () => {
    // No EOL notices ship bundled today; feed-delivered ones are merged into the DB.
    getAdvisoryDatabase().advisories.push({
      id: 'TEST-EOL', title: 'test EOL notice', agent: 'openclaw', affectedVersions: '<2026.0.0',
      severity: 'warning', description: 'test EOL notice', published: '2026-01-01', eolNotice: true,
    });
    const ctx = makeContext({ agent: 'openclaw', version: '0.9.5' });
    const result = await adv003.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.message).toContain('end-of-life');
  });

  it('passes for current version', async () => {
    const ctx = makeContext({ agent: 'openclaw', version: '1.6.0' });
    const result = await adv003.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('passes when version not detected', async () => {
    const ctx = makeContext({ agent: 'openclaw', version: undefined });
    const result = await adv003.run(ctx);
    expect(result.passed).toBe(true);
    expect(result.message).toContain('not detected');
  });
});

describe('ADV-004: Known Exploit Available', () => {
  beforeEach(() => reloadAdvisoryDatabase());

  it('detects exploitable vulnerability', async () => {
    // Cursor 2.9.0 is affected by CVE-2026-50549, which has exploitAvailable
    const ctx = makeContext({ agent: 'cursor-cli', version: '2.9.0' });
    const result = await adv004.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.message).toContain('IMMEDIATE UPDATE');
    expect(result.evidence?.some(e => e.detail?.includes('EXPLOIT AVAILABLE'))).toBe(true);
  });

  it('passes for fixed version', async () => {
    const ctx = makeContext({ agent: 'cursor-cli', version: '3.0.0' });
    const result = await adv004.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('passes when version not detected', async () => {
    const ctx = makeContext({ agent: 'openclaw', version: undefined });
    const result = await adv004.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('detects exploitable vulnerability for other agents', async () => {
    // Gemini CLI 0.39.0 is affected by CVE-2026-12537 (exploitAvailable, fixed in 0.39.1)
    const ctx = makeContext({ agent: 'gemini-cli', version: '0.39.0' });
    const result = await adv004.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.message).toMatch(/^(?:1 vulnerability with a known exploit affects|\d+ vulnerabilities with known exploits affect) /);
  });
});

describe('ADV-005: Config-Based Advisory', () => {
  beforeEach(() => reloadAdvisoryDatabase());

  it('detects dangerous auto_approve_tools wildcard', async () => {
    const config = makeConfig({ auto_approve_tools: '*' });
    const ctx = makeContext({ agent: 'openclaw' }, [config]);
    const result = await adv005.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.evidence?.some(e => e.detail?.includes('auto_approve_tools'))).toBe(true);
  });

  it('detects auto_approve_tools = all', async () => {
    const config = makeConfig({ auto_approve_tools: 'all' });
    const ctx = makeContext({ agent: 'openclaw' }, [config]);
    const result = await adv005.run(ctx);
    expect(result.passed).toBe(false);
  });

  it('passes for safe config', async () => {
    const config = makeConfig({ auto_approve_tools: 'web-search,calculator' });
    const ctx = makeContext({ agent: 'openclaw' }, [config]);
    const result = await adv005.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('passes when no configs present', async () => {
    const ctx = makeContext({ agent: 'openclaw' }, []);
    const result = await adv005.run(ctx);
    expect(result.passed).toBe(true);
  });
});

describe('Advisory checks evaluate every installed CLI copy', () => {
  beforeEach(() => reloadAdvisoryDatabase());

  const oldCopy = '/home/u/.nvm/versions/node/v22.22.1/bin/openclaw';

  it('ADV-001 flags a vulnerable older copy even when the primary is fixed', async () => {
    const ctx = makeContext({
      agent: 'openclaw',
      version: '2026.9.4',
      otherInstalls: [{ path: oldCopy, version: '2026.3.13' }],
    });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.message).toContain(`v2026.3.13 at ${oldCopy}`);
    const hit = result.evidence?.find(e => e.detail?.includes('CVE-2026-35641'));
    expect(hit?.file).toBe(oldCopy);
    expect(hit?.detail).toContain('affects installed copy');
  });

  it('ADV-001 passes when every copy is fixed, and ignores copies of unknown version', async () => {
    const ctx = makeContext({
      agent: 'openclaw',
      version: '2026.9.4',
      otherInstalls: [{ path: '/usr/bin/openclaw', version: '2026.8.1' }, { path: '/opt/openclaw' }],
    });
    expect((await adv001.run(ctx)).passed).toBe(true);
  });

  it('ADV-001 reports primary and copy together, counting each advisory once', async () => {
    const ctx = makeContext({
      agent: 'openclaw',
      version: '2026.3.13',
      otherInstalls: [{ path: oldCopy, version: '2026.3.10' }],
    });
    const result = await adv001.run(ctx);
    expect(result.message).toMatch(/affect openclaw v2026\.3\.13 \(and v2026\.3\.10 at /);
    const count = Number(/^(\d+) known/.exec(result.message)?.[1]);
    const ids = new Set(result.evidence!.map(e => e.detail!.split(':')[0]));
    expect(count).toBe(ids.size);
  });

  it('ADV-001 still runs when only another copy has a known version', async () => {
    const ctx = makeContext({
      agent: 'openclaw',
      version: undefined,
      otherInstalls: [{ path: oldCopy, version: '2026.3.13' }],
    });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.message).toContain(`an installed openclaw copy (v2026.3.13 at ${oldCopy})`);
  });
});
