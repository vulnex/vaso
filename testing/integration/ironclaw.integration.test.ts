import { describe, it, expect, beforeAll } from 'vitest';
import type { ScanResult } from '../../src/core/types.js';
import {
  runVasoScan,
  getAgentResult,
  expectCheckFailed,
  expectCheckPassed,
} from './helpers.js';

describe('IronClaw Insecure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/ironclaw.Dockerfile',
      buildArgs: { SCENARIO: 'insecure' },
    });
  });

  it('should detect the IronClaw agent', () => {
    const agent = getAgentResult(result, 'ironclaw');
    expect(agent).toBeDefined();
    expect(agent!.agent).toBe('ironclaw');
  });

  it('should detect HTTP webhook public bind (IC-001)', () => {
    const check = expectCheckFailed(result, 'IC-001');
    expect(check.severity).toBe('critical');
  });

  it('should detect no TLS on listeners (IC-002)', () => {
    const check = expectCheckFailed(result, 'IC-002');
    expect(check.severity).toBe('critical');
  });

  it('should detect orchestrator public bind (IC-003)', () => {
    const check = expectCheckFailed(result, 'IC-003');
    expect(check.severity).toBe('critical');
  });

  it('should detect missing gateway auth token (IC-004)', () => {
    const check = expectCheckFailed(result, 'IC-004');
    expect(check.severity).toBe('warning');
  });

  it('should detect sandbox disabled (IC-005)', () => {
    const check = expectCheckFailed(result, 'IC-005');
    expect(check.severity).toBe('critical');
  });

  it('should detect full access sandbox policy (IC-006)', () => {
    const check = expectCheckFailed(result, 'IC-006');
    expect(check.severity).toBe('critical');
  });

  it('should detect auto-approve tools (IC-007)', () => {
    const check = expectCheckFailed(result, 'IC-007');
    expect(check.severity).toBe('critical');
  });

  it('should detect local tools bypass (IC-008)', () => {
    const check = expectCheckFailed(result, 'IC-008');
    expect(check.severity).toBe('warning');
  });

  it('should detect secrets key in env (IC-009)', () => {
    const check = expectCheckFailed(result, 'IC-009');
    expect(check.severity).toBe('critical');
  });

  it('should detect Telegram without owner ID (IC-010)', () => {
    const check = expectCheckFailed(result, 'IC-010');
    expect(check.severity).toBe('warning');
  });

  it('should detect broad sandbox domains (IC-011)', () => {
    const check = expectCheckFailed(result, 'IC-011');
    expect(check.severity).toBe('warning');
  });

  it('should detect Docker auto-pull without digest (IC-012)', () => {
    const check = expectCheckFailed(result, 'IC-012');
    expect(check.severity).toBe('warning');
  });

  it('should also detect generic checks (CFG-001)', () => {
    expectCheckFailed(result, 'CFG-001');
  });

  it('should produce a low security score', () => {
    const agent = getAgentResult(result, 'ironclaw');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeLessThan(30);
  });

  it('should assign a failing grade', () => {
    const agent = getAgentResult(result, 'ironclaw');
    expect(agent).toBeDefined();
    expect(agent!.grade).toBe('F');
  });
});

describe('IronClaw Secure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/ironclaw.Dockerfile',
      buildArgs: { SCENARIO: 'secure' },
    });
  });

  it('should detect the IronClaw agent', () => {
    const agent = getAgentResult(result, 'ironclaw');
    expect(agent).toBeDefined();
  });

  it('should pass webhook binding check (IC-001)', () => {
    expectCheckPassed(result, 'IC-001');
  });

  it('should pass sandbox check (IC-005)', () => {
    expectCheckPassed(result, 'IC-005');
  });

  it('should pass auto-approve check (IC-007)', () => {
    expectCheckPassed(result, 'IC-007');
  });

  it('should produce a high security score', () => {
    const agent = getAgentResult(result, 'ironclaw');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeGreaterThanOrEqual(80);
  });
});
