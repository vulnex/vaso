import { describe, it, expect, beforeAll } from 'vitest';
import type { ScanResult } from '../../src/core/types.js';
import {
  runVasoScan,
  getAgentResult,
  expectCheckFailed,
  expectCheckPassed,
} from './helpers.js';

describe('Nanobot Insecure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/nanobot.Dockerfile',
      buildArgs: { SCENARIO: 'insecure' },
    });
  });

  it('should detect the Nanobot agent', () => {
    const agent = getAgentResult(result, 'nanobot');
    expect(agent).toBeDefined();
    expect(agent!.agent).toBe('nanobot');
  });

  it('should detect empty channel allowFrom (NB-001)', () => {
    const check = expectCheckFailed(result, 'NB-001');
    expect(check.severity).toBe('critical');
  });

  it('should detect plaintext secrets (NB-002)', () => {
    const check = expectCheckFailed(result, 'NB-002');
    expect(check.severity).toBe('critical');
  });

  it('should detect workspace sandboxing off (NB-003)', () => {
    const check = expectCheckFailed(result, 'NB-003');
    expect(check.severity).toBe('warning');
  });

  it('should detect weak shell filtering (NB-004)', () => {
    const check = expectCheckFailed(result, 'NB-004');
    expect(check.severity).toBe('critical');
  });

  it('should detect no SSRF protection (NB-005)', () => {
    const check = expectCheckFailed(result, 'NB-005');
    expect(check.severity).toBe('warning');
  });

  it('should detect heartbeat injection risk (NB-006)', () => {
    const check = expectCheckFailed(result, 'NB-006');
    expect(check.severity).toBe('warning');
  });

  it('should detect memory injection risk (NB-007)', () => {
    const check = expectCheckFailed(result, 'NB-007');
    expect(check.severity).toBe('critical');
  });

  it('should detect WhatsApp bridge without token (NB-008)', () => {
    const check = expectCheckFailed(result, 'NB-008');
    expect(check.severity).toBe('warning');
  });

  it('should detect unencrypted sessions (NB-009)', () => {
    const check = expectCheckFailed(result, 'NB-009');
    expect(check.severity).toBe('warning');
  });

  it('should detect cron arbitrary channels (NB-010)', () => {
    const check = expectCheckFailed(result, 'NB-010');
    expect(check.severity).toBe('warning');
  });

  it('should detect no rate limiting (NB-011)', () => {
    const check = expectCheckFailed(result, 'NB-011');
    expect(check.severity).toBe('warning');
  });

  it('should detect ClawHub via npx (NB-012)', () => {
    const check = expectCheckFailed(result, 'NB-012');
    expect(check.severity).toBe('warning');
  });

  it('should produce a low security score', () => {
    const agent = getAgentResult(result, 'nanobot');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeLessThan(30);
  });
});

describe('Nanobot Secure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/nanobot.Dockerfile',
      buildArgs: { SCENARIO: 'secure' },
    });
  });

  it('should detect the Nanobot agent', () => {
    const agent = getAgentResult(result, 'nanobot');
    expect(agent).toBeDefined();
  });

  it('should pass workspace restriction check (NB-003)', () => {
    expectCheckPassed(result, 'NB-003');
  });

  it('should produce a reasonable security score', () => {
    // Generic CFG-005/006/010 warnings still apply to the minimum-secure
    // Nanobot fixture; the check that matters is the gap from insecure
    // (score < 30) to secure.
    const agent = getAgentResult(result, 'nanobot');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeGreaterThanOrEqual(65);
  });
});
