import { describe, it, expect, beforeAll } from 'vitest';
import type { ScanResult } from '../../src/core/types.js';
import {
  runVasoScan,
  findCheck,
  getAgentResult,
  expectCheckFailed,
  expectCheckPassed,
} from './helpers.js';

describe('OpenClaw Insecure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/openclaw.Dockerfile',
      buildArgs: { SCENARIO: 'insecure' },
    });
  });

  it('should detect the OpenClaw agent', () => {
    const agent = getAgentResult(result, 'openclaw');
    expect(agent).toBeDefined();
    expect(agent!.agent).toBe('openclaw');
  });

  it('should detect gateway bound to 0.0.0.0 (CFG-001)', () => {
    const check = expectCheckFailed(result, 'CFG-001');
    expect(check.severity).toBe('critical');
  });

  it('should detect exposed API key in config (CFG-002)', () => {
    const check = expectCheckFailed(result, 'CFG-002');
    expect(check.severity).toBe('critical');
  });

  it('should detect TLS not configured (CFG-004)', () => {
    const check = expectCheckFailed(result, 'CFG-004');
    expect(check.severity).toBe('warning');
  });

  it('does not run CFG-007 on OpenClaw (its webhooks are hooks.*, not webhooks[])', () => {
    expect(getAgentResult(result, 'openclaw')?.results.find(r => r.id === 'CFG-007')).toBeUndefined();
  });

  it('should detect sandbox disabled (CFG-008)', () => {
    const check = expectCheckFailed(result, 'CFG-008');
    expect(check.severity).toBe('critical');
  });

  it('should detect default credentials (CFG-009)', () => {
    const check = expectCheckFailed(result, 'CFG-009');
    expect(check.severity).toBe('critical');
  });

  it('should detect a gateway auth rate limit tuned too weak (CFG-010)', () => {
    const check = expectCheckFailed(result, 'CFG-010');
    expect(check.severity).toBe('warning');
  });

  it('should detect auth bypass enabled (CFG-012)', () => {
    const check = expectCheckFailed(result, 'CFG-012');
    expect(check.severity).toBe('critical');
  });

  it('should detect open DM policy (CFG-013)', () => {
    const check = expectCheckFailed(result, 'CFG-013');
    expect(check.severity).toBe('warning');
  });

  it('does not run CFG-014 on OpenClaw (its tool policy is tools.profile/allow/deny)', () => {
    expect(getAgentResult(result, 'openclaw')?.results.find(r => r.id === 'CFG-014')).toBeUndefined();
  });

  it('should detect mDNS broadcast (CFG-015)', () => {
    const check = expectCheckFailed(result, 'CFG-015');
    expect(check.severity).toBe('info');
  });

  it('should detect data exfiltration flow (SKL-001)', () => {
    const check = expectCheckFailed(result, 'SKL-001');
    expect(check.severity).toBe('critical');
  });

  it('should detect obfuscated code (SKL-002)', () => {
    const check = expectCheckFailed(result, 'SKL-002');
    expect(check.severity).toBe('warning');
  });

  it('should detect eval/exec usage (SKL-003)', () => {
    const check = expectCheckFailed(result, 'SKL-003');
    expect(check.severity).toBe('critical');
  });

  it('should detect reverse shell pattern (SKL-005)', () => {
    const check = expectCheckFailed(result, 'SKL-005');
    expect(check.severity).toBe('critical');
  });

  it('should detect prompt injection in SKILL.md (SKL-007)', () => {
    const check = expectCheckFailed(result, 'SKL-007');
    expect(check.severity).toBe('warning');
  });

  it('should detect C2 IP address (IOC-001)', () => {
    const check = expectCheckFailed(result, 'IOC-001');
    expect(check.severity).toBe('critical');
  });

  it('should detect malicious domain (IOC-002)', () => {
    const check = expectCheckFailed(result, 'IOC-002');
    expect(check.severity).toBe('critical');
  });

  it('should detect typosquatting skill name (IOC-005)', () => {
    const check = expectCheckFailed(result, 'IOC-005');
    expect(check.severity).toBe('warning');
  });

  it('should produce a low security score', () => {
    const agent = getAgentResult(result, 'openclaw');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeLessThan(50);
  });

  it('should assign a failing grade', () => {
    const agent = getAgentResult(result, 'openclaw');
    expect(agent).toBeDefined();
    expect(agent!.grade).toBe('F');
  });
});

describe('OpenClaw Secure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/openclaw.Dockerfile',
      buildArgs: { SCENARIO: 'secure' },
    });
  });

  it('should detect the OpenClaw agent', () => {
    const agent = getAgentResult(result, 'openclaw');
    expect(agent).toBeDefined();
  });

  it('should pass gateway binding check (CFG-001)', () => {
    expectCheckPassed(result, 'CFG-001');
  });

  it('should pass TLS check (CFG-004)', () => {
    expectCheckPassed(result, 'CFG-004');
  });

  it('should pass sandbox check (CFG-008)', () => {
    expectCheckPassed(result, 'CFG-008');
  });

  it('should pass auth bypass check (CFG-012)', () => {
    expectCheckPassed(result, 'CFG-012');
  });

  it('should pass rate limiting check (CFG-010)', () => {
    expectCheckPassed(result, 'CFG-010');
  });

  it('should pass DM policy check (CFG-013)', () => {
    expectCheckPassed(result, 'CFG-013');
  });

  it('does not run CFG-014 on OpenClaw', () => {
    expect(getAgentResult(result, 'openclaw')?.results.find(r => r.id === 'CFG-014')).toBeUndefined();
  });

  it('should produce a high security score', () => {
    const agent = getAgentResult(result, 'openclaw');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeGreaterThanOrEqual(90);
  });

  it('should assign a passing grade', () => {
    const agent = getAgentResult(result, 'openclaw');
    expect(agent).toBeDefined();
    expect(['A', 'B']).toContain(agent!.grade);
  });
});
