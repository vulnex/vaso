import { describe, it, expect, beforeAll } from 'vitest';
import type { ScanResult } from '../../src/core/types.js';
import {
  runVasoScan,
  getAgentResult,
  expectCheckFailed,
  expectCheckPassed,
} from './helpers.js';

describe('NanoClaw Insecure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/nanoclaw.Dockerfile',
      buildArgs: { SCENARIO: 'insecure' },
    });
  });

  it('should detect the NanoClaw agent', () => {
    const agent = getAgentResult(result, 'nanoclaw');
    expect(agent).toBeDefined();
    expect(agent!.agent).toBe('nanoclaw');
  });

  it('should detect gateway bound to 0.0.0.0 (CFG-001)', () => {
    const check = expectCheckFailed(result, 'CFG-001');
    expect(check.severity).toBe('critical');
  });

  it('should detect sandbox disabled (CFG-008)', () => {
    const check = expectCheckFailed(result, 'CFG-008');
    expect(check.severity).toBe('critical');
  });

  it('should detect auth bypass (CFG-012)', () => {
    const check = expectCheckFailed(result, 'CFG-012');
    expect(check.severity).toBe('critical');
  });

  it('should detect open DM policy (CFG-013)', () => {
    const check = expectCheckFailed(result, 'CFG-013');
    expect(check.severity).toBe('warning');
  });

  it('should detect permissive tool policy (CFG-014)', () => {
    const check = expectCheckFailed(result, 'CFG-014');
    expect(check.severity).toBe('warning');
  });

  it('should detect eval/exec in malicious skill (SKL-003)', () => {
    const check = expectCheckFailed(result, 'SKL-003');
    expect(check.severity).toBe('critical');
  });

  it('should detect C2 IP in malicious skill (IOC-001)', () => {
    const check = expectCheckFailed(result, 'IOC-001');
    expect(check.severity).toBe('critical');
  });

  it('should produce a low security score', () => {
    const agent = getAgentResult(result, 'nanoclaw');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeLessThan(50);
  });
});

describe('NanoClaw Secure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/nanoclaw.Dockerfile',
      buildArgs: { SCENARIO: 'secure' },
    });
  });

  it('should detect the NanoClaw agent', () => {
    const agent = getAgentResult(result, 'nanoclaw');
    expect(agent).toBeDefined();
  });

  it('should pass gateway binding check (CFG-001)', () => {
    expectCheckPassed(result, 'CFG-001');
  });

  it('should pass sandbox check (CFG-008)', () => {
    expectCheckPassed(result, 'CFG-008');
  });

  it('should pass rate limiting check (CFG-010)', () => {
    expectCheckPassed(result, 'CFG-010');
  });

  it('should produce a high security score', () => {
    // Generic CFG-005/006 warnings still apply to the minimum-secure
    // NanoClaw fixture; the gap from insecure to secure is the load-bearing
    // signal, not an aspirational A-grade.
    const agent = getAgentResult(result, 'nanoclaw');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeGreaterThanOrEqual(75);
  });
});
