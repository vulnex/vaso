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

  it('should detect plaintext secrets (ZC-001)', () => {
    // Files are 644 but /root is 0700 — not reachable by other users, so the
    // finding stays at warning rather than escalating to critical.
    const check = expectCheckFailed(result, 'ZC-001');
    expect(check.severity).toBe('warning');
  });

  it('should detect legacy XOR encryption (ZC-002)', () => {
    const check = expectCheckFailed(result, 'ZC-002');
    expect(check.severity).toBe('warning');
  });

  it('should detect gateway exposed without TLS or tunnel (ZC-003)', () => {
    const check = expectCheckFailed(result, 'ZC-003');
    expect(check.severity).toBe('critical');
  });

  it('should detect pairing disabled on an exposed gateway (ZC-004)', () => {
    const check = expectCheckFailed(result, 'ZC-004');
    expect(check.severity).toBe('critical');
  });

  it('should detect full autonomy mode (ZC-005)', () => {
    const check = expectCheckFailed(result, 'ZC-005');
    expect(check.severity).toBe('critical');
  });

  it('should detect unrestricted filesystem (ZC-006)', () => {
    const check = expectCheckFailed(result, 'ZC-006');
    expect(check.severity).toBe('warning');
  });

  it('should detect open-to-anyone peer group (ZC-007)', () => {
    const check = expectCheckFailed(result, 'ZC-007');
    expect(check.severity).toBe('critical');
  });

  it('should detect unvetted skill sources (ZC-008)', () => {
    const check = expectCheckFailed(result, 'ZC-008');
    expect(check.severity).toBe('warning');
  });

  it('should pass WhatsApp Web session check when no WhatsApp channel (ZC-009)', () => {
    expectCheckPassed(result, 'ZC-009');
  });

  it('should detect Composio integration (ZC-010)', () => {
    const check = expectCheckFailed(result, 'ZC-010');
    expect(check.severity).toBe('info');
  });

  it('should detect browser automation without approval (ZC-011)', () => {
    const check = expectCheckFailed(result, 'ZC-011');
    expect(check.severity).toBe('warning');
  });

  it('should detect HTTP tool reaching private hosts (ZC-012)', () => {
    const check = expectCheckFailed(result, 'ZC-012');
    expect(check.severity).toBe('warning');
  });

  it('should detect .secret_key permissions (ZC-013)', () => {
    // 644 inside /root (0700): mitigated by the parent directory -> info.
    const check = expectCheckFailed(result, 'ZC-013');
    expect(check.severity).toBe('info');
  });

  it('should detect sandbox disabled (ZC-014)', () => {
    const check = expectCheckFailed(result, 'ZC-014');
    expect(check.severity).toBe('warning');
  });

  it('should detect unrestricted shell execution (ZC-015)', () => {
    const check = expectCheckFailed(result, 'ZC-015');
    expect(check.severity).toBe('critical');
  });

  it('should detect relaxed gateway safeguards (ZC-016)', () => {
    const check = expectCheckFailed(result, 'ZC-016');
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

  it('should pass the remaining ZeroClaw checks', () => {
    for (const id of ['ZC-001', 'ZC-002', 'ZC-004', 'ZC-007', 'ZC-008', 'ZC-011', 'ZC-012', 'ZC-013', 'ZC-014', 'ZC-015', 'ZC-016']) {
      expectCheckPassed(result, id);
    }
  });

  it('should produce a high security score', () => {
    const agent = getAgentResult(result, 'zeroclaw');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeGreaterThanOrEqual(80);
  });
});
