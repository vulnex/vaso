import { describe, it, expect, beforeEach } from 'vitest';
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
    expect(result.evidence?.length).toBeGreaterThan(0);
    expect(result.evidence?.some(e => e.detail?.includes('CVE-2026-35641'))).toBe(true);
  });

  it('passes for fixed version', async () => {
    // 2026.4.20 is the fixed version of the newest bundled OpenClaw advisory
    // (CVE-2026-44999) and clears every earlier calver range.
    const ctx = makeContext({ agent: 'openclaw', version: '2026.4.20' });
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

  it('passes a coding agent at the GhostApproval fix version', async () => {
    const ctx = makeContext({ agent: 'cursor-cli', version: '3.0.0' });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(true);
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
      otherInstalls: [{ path: '/usr/bin/openclaw', version: '2026.4.20' }, { path: '/opt/openclaw' }],
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
