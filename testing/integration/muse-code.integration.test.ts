import { describe, it, expect, beforeAll } from 'vitest';
import type { ScanResult } from '../../src/core/types.js';
import {
  runVasoScan,
  getAgentResult,
  expectCheckFailed,
  expectCheckPassed,
} from './helpers.js';

const MSC = ['MSC-001', 'MSC-002', 'MSC-003', 'MSC-004', 'MSC-005', 'MSC-006', 'MSC-007', 'MSC-008', 'MSC-009', 'MSC-010', 'MSC-011', 'MSC-012'];

describe('Meta Muse Code Insecure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/muse-code.Dockerfile',
      buildArgs: { SCENARIO: 'insecure' },
      env: { MUSE_PERMISSION_PROFILE_FAIL_OPEN: '1' },
      cliArgs: ['-a', 'muse-code'],
    });
  });

  it('detects Muse Code from its launcher and versions it without running it', () => {
    const agent = getAgentResult(result, 'muse-code');
    expect(agent).toBeDefined();
    expect(agent!.installation.version).toBe('1.4.25');
    expect(agent!.installation.cliBinary).toBe('/root/.local/bin/muse');
    expect(agent!.installation.installDir).toBe('/root/.config/muse');
  });

  it('reports a default profile without approval or sandbox (MSC-001/002)', () => {
    expect(expectCheckFailed(result, 'MSC-001').severity).toBe('critical');
    expect(expectCheckFailed(result, 'MSC-001').fixable).toBe(true);
    expect(expectCheckFailed(result, 'MSC-002').evidence).toHaveLength(2);
  });

  it('reports a readable auth.json and world-readable transcripts (MSC-003/008)', () => {
    expect(expectCheckFailed(result, 'MSC-003').severity).toBe('critical');
    const sessions = expectCheckFailed(result, 'MSC-008');
    expect(sessions.severity).toBe('warning');
    expect(sessions.evidence?.some(e => e.file?.endsWith('/session.jsonl') && !e.mitigated)).toBe(true);
  });

  it('reports MCP secrets, unpinned packages and http URLs without printing the token (MSC-004/005/006)', () => {
    const secrets = expectCheckFailed(result, 'MSC-004');
    expect(JSON.stringify(secrets.evidence)).not.toContain('ghp_Q4k8');
    expectCheckFailed(result, 'MSC-005');
    expect(expectCheckFailed(result, 'MSC-006').severity).toBe('critical');
  });

  it('reports the download-and-run hook and the endpoint redirect (MSC-007/011)', () => {
    expect(expectCheckFailed(result, 'MSC-007').severity).toBe('critical');
    expectCheckFailed(result, 'MSC-011');
  });

  it('reports the world-writable settings.json and the fail-open env override (MSC-009/010)', () => {
    const writable = expectCheckFailed(result, 'MSC-009');
    expect(writable.evidence?.some(e => e.file === '/root/.config/muse/settings.json')).toBe(true);
    expectCheckFailed(result, 'MSC-010');
  });

  it('produces a failing score', () => {
    expect(getAgentResult(result, 'muse-code')!.score).toBeLessThan(50);
  });
});

describe('Meta Muse Code Secure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/muse-code.Dockerfile',
      buildArgs: { SCENARIO: 'secure' },
      cliArgs: ['-a', 'muse-code'],
    });
  });

  it('detects the agent', () => {
    expect(getAgentResult(result, 'muse-code')?.installation.version).toBe('1.4.25');
  });

  it('passes every Muse Code check', () => {
    for (const id of MSC) expectCheckPassed(result, id);
  });

  it('has no warning or critical finding', () => {
    const agent = getAgentResult(result, 'muse-code')!;
    const severe = agent.results.filter(r => !r.passed && r.severity !== 'info' && r.category !== 'advisory');
    expect(severe.map(r => r.id)).toEqual([]);
  });
});

describe('Meta Muse Code MCP discovery', () => {
  it('vaso mcp list finds the servers in ~/.config/muse/settings.json, secrets masked', async () => {
    const result = await runVasoScan({
      dockerfile: 'testing/docker/agents/muse-code.Dockerfile',
      buildArgs: { SCENARIO: 'insecure' },
      command: ['mcp', 'list'],
    }) as unknown as { configs: { source: string; agents?: string[]; filePath: string; servers: { name: string }[] }[] };
    const muse = result.configs.find(c => c.agents?.includes('muse-code') && c.filePath === '/root/.config/muse/settings.json');
    expect(muse?.source).toBe('Muse Code');
    expect(muse!.servers.map(s => s.name).sort()).toEqual(['github', 'intranet']);
    expect(JSON.stringify(muse)).not.toContain('ghp_Q4k8');
  });
});
