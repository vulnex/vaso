import { describe, it, expect, beforeAll } from 'vitest';
import type { ScanResult } from '../../src/core/types.js';
import {
  runVasoScan,
  getAgentResult,
  expectCheckFailed,
  expectCheckPassed,
} from './helpers.js';

describe('PicoClaw Insecure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/picoclaw.Dockerfile',
      buildArgs: { SCENARIO: 'insecure' },
    });
  });

  it('should detect the PicoClaw agent', () => {
    const agent = getAgentResult(result, 'picoclaw');
    expect(agent).toBeDefined();
    expect(agent!.agent).toBe('picoclaw');
  });

  it('treats .security.yml as the secret store (CFG-002), leaving its exposure to CFG-003', () => {
    const agent = getAgentResult(result, 'picoclaw');
    const check = agent!.results.find(r => r.id === 'CFG-002');
    expect(check?.evidence?.some(e => e.file?.endsWith('/.picoclaw/.security.yml')) ?? false).toBe(false);
  });

  it('should detect gateway bound to 0.0.0.0 (CFG-001)', () => {
    const check = expectCheckFailed(result, 'CFG-001');
    expect(check.severity).toBe('critical');
  });

  it('should detect the gateway exposed on all interfaces (NET-001)', () => {
    const check = expectCheckFailed(result, 'NET-001');
    expect(check.severity).toBe('critical');
  });

  it('should detect world-readable secret files (CFG-003)', () => {
    const check = expectCheckFailed(result, 'CFG-003');
    expect(check.evidence?.some(e => e.file?.endsWith('/.picoclaw/.security.yml'))).toBe(true);
  });

  it('should detect malicious domain in skill (IOC-002)', () => {
    const check = expectCheckFailed(result, 'IOC-002');
    expect(check.severity).toBe('critical');
  });

  it('should detect PicoClaw-specific exposures (PCL-001/002/003/004/006)', () => {
    for (const id of ['PCL-001', 'PCL-002', 'PCL-003', 'PCL-004', 'PCL-006']) expectCheckFailed(result, id);
    expect(expectCheckFailed(result, 'PCL-003').severity).toBe('critical');
    expect(expectCheckFailed(result, 'PCL-006').severity).toBe('critical');
  });

  it('should produce a low security score', () => {
    const agent = getAgentResult(result, 'picoclaw');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeLessThan(50);
  });
});

describe('PicoClaw Secure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/picoclaw.Dockerfile',
      buildArgs: { SCENARIO: 'secure' },
    });
  });

  it('should detect the PicoClaw agent', () => {
    const agent = getAgentResult(result, 'picoclaw');
    expect(agent).toBeDefined();
  });

  it('should pass gateway binding check (CFG-001)', () => {
    expectCheckPassed(result, 'CFG-001');
  });

  it('should pass the NET-001 exposure check (loopback gateway)', () => {
    expectCheckPassed(result, 'NET-001');
  });

  it('should pass the credential permission check (CFG-003)', () => {
    expectCheckPassed(result, 'CFG-003');
  });

  it('should pass API key check — secrets are enc:// (CFG-002)', () => {
    expectCheckPassed(result, 'CFG-002');
  });

  it('should pass every PicoClaw-specific check (PCL-001–007)', () => {
    for (let n = 1; n <= 7; n++) expectCheckPassed(result, `PCL-00${n}`);
  });

  it('should produce a high security score', () => {
    const agent = getAgentResult(result, 'picoclaw');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeGreaterThanOrEqual(90);
  });
});
