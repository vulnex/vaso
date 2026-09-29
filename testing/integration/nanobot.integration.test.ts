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

  it('should detect a channel open to any sender (NB-001)', () => {
    const check = expectCheckFailed(result, 'NB-001');
    expect(check.severity).toBe('critical');
  });

  it('should detect plaintext secrets (NB-002)', () => {
    const check = expectCheckFailed(result, 'NB-002');
    // config.json is 0644 under an exposed home → escalated
    expect(check.severity).toBe('critical');
  });

  it('should detect workspace restriction off (NB-003)', () => {
    const check = expectCheckFailed(result, 'NB-003');
    expect(check.severity).toBe('warning');
  });

  it('should detect a catch-all exec allow pattern (NB-004)', () => {
    const check = expectCheckFailed(result, 'NB-004');
    expect(check.severity).toBe('critical');
  });

  it('should detect a metadata-covering SSRF whitelist (NB-005)', () => {
    const check = expectCheckFailed(result, 'NB-005');
    expect(check.severity).toBe('warning');
  });

  it('should detect a world-writable HEARTBEAT.md (NB-006)', () => {
    const check = expectCheckFailed(result, 'NB-006');
    expect(check.severity).toBe('warning');
  });

  it('should detect a world-writable MEMORY.md (NB-007)', () => {
    const check = expectCheckFailed(result, 'NB-007');
    expect(check.severity).toBe('critical');
  });

  it('should detect an unauthenticated network websocket channel (NB-008)', () => {
    const check = expectCheckFailed(result, 'NB-008');
    expect(check.severity).toBe('critical');
  });

  it('should detect readable chat history (NB-009)', () => {
    const check = expectCheckFailed(result, 'NB-009');
    expect(check.severity).toBe('warning');
  });

  it('should detect a world-writable cron job store (NB-010)', () => {
    const check = expectCheckFailed(result, 'NB-010');
    expect(check.severity).toBe('warning');
  });

  it('should detect an unauthenticated serve API (NB-011)', () => {
    const check = expectCheckFailed(result, 'NB-011');
    expect(check.severity).toBe('critical');
  });

  it('should detect an unpinned npx MCP server (NB-012)', () => {
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

  it('should pass every Nanobot check', () => {
    for (const id of ['NB-001', 'NB-002', 'NB-003', 'NB-004', 'NB-005', 'NB-006',
      'NB-007', 'NB-008', 'NB-009', 'NB-010', 'NB-011', 'NB-012']) {
      expectCheckPassed(result, id);
    }
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
