import { describe, it, expect, beforeAll } from 'vitest';
import type { ScanResult } from '../../src/core/types.js';
import {
  runVasoScan,
  getAgentResult,
  expectCheckFailed,
  expectCheckPassed,
} from './helpers.js';

describe('ZeroClaw Insecure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/zeroclaw.Dockerfile',
      buildArgs: { SCENARIO: 'insecure' },
    });
  });

  it('should detect the ZeroClaw agent', () => {
    const agent = getAgentResult(result, 'zeroclaw');
    expect(agent).toBeDefined();
    expect(agent!.agent).toBe('zeroclaw');
  });

  it('should detect plaintext API keys (ZC-001)', () => {
    const check = expectCheckFailed(result, 'ZC-001');
    expect(check.severity).toBe('critical');
  });

  it('should detect legacy XOR encryption (ZC-002)', () => {
    const check = expectCheckFailed(result, 'ZC-002');
    expect(check.severity).toBe('critical');
  });

  it('should detect public bind without tunnel (ZC-003)', () => {
    const check = expectCheckFailed(result, 'ZC-003');
    expect(check.severity).toBe('critical');
  });

  it('should detect pairing disabled (ZC-004)', () => {
    const check = expectCheckFailed(result, 'ZC-004');
    expect(check.severity).toBe('warning');
  });

  it('should detect full autonomy mode (ZC-005)', () => {
    const check = expectCheckFailed(result, 'ZC-005');
    expect(check.severity).toBe('critical');
  });

  it('should detect unrestricted filesystem (ZC-006)', () => {
    const check = expectCheckFailed(result, 'ZC-006');
    expect(check.severity).toBe('warning');
  });

  it('should detect wildcard channel users (ZC-007)', () => {
    const check = expectCheckFailed(result, 'ZC-007');
    expect(check.severity).toBe('critical');
  });

  it('should detect open skills enabled (ZC-008)', () => {
    const check = expectCheckFailed(result, 'ZC-008');
    expect(check.severity).toBe('warning');
  });

  it('should detect missing WhatsApp app secret (ZC-009)', () => {
    const check = expectCheckFailed(result, 'ZC-009');
    expect(check.severity).toBe('warning');
  });

  it('should detect Composio integration (ZC-010)', () => {
    const check = expectCheckFailed(result, 'ZC-010');
    expect(check.severity).toBe('info');
  });

  it('should detect browser without domain allowlist (ZC-011)', () => {
    const check = expectCheckFailed(result, 'ZC-011');
    expect(check.severity).toBe('warning');
  });

  it('should detect HTTP tool without domain filter (ZC-012)', () => {
    const check = expectCheckFailed(result, 'ZC-012');
    expect(check.severity).toBe('warning');
  });

  it('should detect .secret_key permissions (ZC-013)', () => {
    const check = expectCheckFailed(result, 'ZC-013');
    expect(check.severity).toBe('critical');
  });

  it('should detect no OS-level sandbox (ZC-014)', () => {
    const check = expectCheckFailed(result, 'ZC-014');
    expect(check.severity).toBe('warning');
  });

  it('should also detect generic gateway binding (CFG-001)', () => {
    expectCheckFailed(result, 'CFG-001');
  });

  it('should produce a low security score', () => {
    const agent = getAgentResult(result, 'zeroclaw');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeLessThan(20);
  });

  it('should assign a failing grade', () => {
    const agent = getAgentResult(result, 'zeroclaw');
    expect(agent).toBeDefined();
    expect(agent!.grade).toBe('F');
  });
});

describe('ZeroClaw Secure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/zeroclaw.Dockerfile',
      buildArgs: { SCENARIO: 'secure' },
    });
  });

  it('should detect the ZeroClaw agent', () => {
    const agent = getAgentResult(result, 'zeroclaw');
    expect(agent).toBeDefined();
  });

  it('should pass public bind check (ZC-003)', () => {
    expectCheckPassed(result, 'ZC-003');
  });

  it('should pass full autonomy check (ZC-005)', () => {
    expectCheckPassed(result, 'ZC-005');
  });

  it('should pass workspace check (ZC-006)', () => {
    expectCheckPassed(result, 'ZC-006');
  });

  it('should produce a high security score', () => {
    const agent = getAgentResult(result, 'zeroclaw');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeGreaterThanOrEqual(80);
  });
});
