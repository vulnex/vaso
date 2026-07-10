import { describe, it, expect, beforeEach } from 'vitest';
import type { ScanContext, AgentInstallation, ParsedConfig } from '../../core/types.js';
import { LocalFSProvider } from '../../core/local-fs-provider.js';
import { adv001 } from './adv-001-version-vuln.js';
import { adv002 } from './adv-002-dependency-vuln.js';
import { adv003 } from './adv-003-eol-version.js';
import { adv004 } from './adv-004-known-exploit.js';
import { adv005 } from './adv-005-config-advisory.js';
import { reloadAdvisoryDatabase } from '../../advisory/database.js';

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
    // OpenClaw 1.4.0 should be affected by CVE-2026-40001 (affects <1.5.3)
    const ctx = makeContext({ agent: 'openclaw', version: '1.4.0' });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.evidence?.length).toBeGreaterThan(0);
    expect(result.evidence?.[0].detail).toContain('CVE-2026-40001');
  });

  it('passes for fixed version', async () => {
    const ctx = makeContext({ agent: 'openclaw', version: '1.6.0' });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('passes when version not detected', async () => {
    const ctx = makeContext({ agent: 'openclaw', version: undefined });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(true);
    expect(result.message).toContain('not detected');
  });

  it('detects vulnerabilities for other agents', async () => {
    // IronClaw 0.3.0 should be affected by CVE-2026-40030 (affects <0.4.0)
    const ctx = makeContext({ agent: 'ironclaw', version: '0.3.0' });
    const result = await adv001.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.evidence?.some(e => e.detail?.includes('CVE-2026-40030'))).toBe(true);
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

  it('detects EOL OpenClaw 0.x version', async () => {
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
    // OpenClaw 1.4.0 is affected by CVE-2026-40001 which has exploitAvailable
    const ctx = makeContext({ agent: 'openclaw', version: '1.4.0' });
    const result = await adv004.run(ctx);
    expect(result.passed).toBe(false);
    expect(result.message).toContain('IMMEDIATE UPDATE');
    expect(result.evidence?.some(e => e.detail?.includes('EXPLOIT AVAILABLE'))).toBe(true);
  });

  it('passes for fixed version', async () => {
    const ctx = makeContext({ agent: 'openclaw', version: '1.6.0' });
    const result = await adv004.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('passes when version not detected', async () => {
    const ctx = makeContext({ agent: 'openclaw', version: undefined });
    const result = await adv004.run(ctx);
    expect(result.passed).toBe(true);
  });

  it('detects exploitable vulnerability for other agents', async () => {
    // NanoClaw 2.2.0 affected by CVE-2026-40010 (exploitAvailable, affects <2.3.1)
    const ctx = makeContext({ agent: 'nanoclaw', version: '2.2.0' });
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
