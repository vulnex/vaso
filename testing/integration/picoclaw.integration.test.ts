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

  it('should detect exposed API key in auth.json (CFG-002)', () => {
    const check = expectCheckFailed(result, 'CFG-002');
    expect(check.severity).toBe('critical');
  });

  it('should detect gateway bound to 0.0.0.0 (CFG-001)', () => {
    const check = expectCheckFailed(result, 'CFG-001');
    expect(check.severity).toBe('critical');
  });

  it('should detect sandbox disabled (CFG-008)', () => {
    const check = expectCheckFailed(result, 'CFG-008');
    expect(check.severity).toBe('critical');
  });

  it('should detect default credentials (CFG-009)', () => {
    const check = expectCheckFailed(result, 'CFG-009');
    expect(check.severity).toBe('critical');
  });

  it('should detect auth mode none (CFG-012)', () => {
    const check = expectCheckFailed(result, 'CFG-012');
    expect(check.severity).toBe('critical');
  });

  it('should detect malicious domain in skill (IOC-002)', () => {
    const check = expectCheckFailed(result, 'IOC-002');
    expect(check.severity).toBe('critical');
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

  it('should pass sandbox check (CFG-008)', () => {
    expectCheckPassed(result, 'CFG-008');
  });

  it('should pass API key check (CFG-002)', () => {
    expectCheckPassed(result, 'CFG-002');
  });

  it('should produce a high security score', () => {
    const agent = getAgentResult(result, 'picoclaw');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeGreaterThanOrEqual(90);
  });
});
