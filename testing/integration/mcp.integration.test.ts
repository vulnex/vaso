import { describe, it, expect, beforeAll } from 'vitest';
import type { ScanResult } from '../../src/core/types.js';
import {
  runVasoScan,
  getAgentResult,
  expectCheckFailed,
  expectCheckPassed,
} from './helpers.js';

describe('MCP Insecure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/mcp.Dockerfile',
      buildArgs: { SCENARIO: 'insecure' },
      command: ['mcp', 'scan', '--path', '/mcp/config.json'],
    });
  });

  it('should detect MCP agent', () => {
    const agent = getAgentResult(result, 'mcp');
    expect(agent).toBeDefined();
    expect(agent!.agent).toBe('mcp');
  });

  it('should discover MCP config (MCP-001)', () => {
    // MCP-001 is informational and always passes
    const check = expectCheckPassed(result, 'MCP-001');
    expect(check.severity).toBe('info');
  });

  it('should detect insecure transport — HTTP on 0.0.0.0 (MCP-002)', () => {
    const check = expectCheckFailed(result, 'MCP-002');
    expect(check.severity).toBe('critical');
  });

  it('should detect plaintext credentials in env (MCP-003)', () => {
    const check = expectCheckFailed(result, 'MCP-003');
    expect(check.severity).toBe('critical');
  });

  it('should detect exec/eval in server source (MCP-004)', () => {
    const check = expectCheckFailed(result, 'MCP-004');
    expect(check.severity).toBe('critical');
  });

  it('should detect unsanitized input injection (MCP-005)', () => {
    const check = expectCheckFailed(result, 'MCP-005');
    expect(check.severity).toBe('critical');
  });

  it('should detect data exfiltration risk (MCP-006)', () => {
    const check = expectCheckFailed(result, 'MCP-006');
    expect(check.severity).toBe('critical');
  });

  it('should detect prompt injection via tool results (MCP-007)', () => {
    const check = expectCheckFailed(result, 'MCP-007');
    expect(check.severity).toBe('warning');
  });

  it('should detect typosquatting server name (MCP-008)', () => {
    const check = expectCheckFailed(result, 'MCP-008');
    expect(check.severity).toBe('warning');
  });

  it('should detect overprivileged permissions (MCP-009)', () => {
    const check = expectCheckFailed(result, 'MCP-009');
    expect(check.severity).toBe('warning');
  });

  it('should detect unpinned package versions (MCP-010)', () => {
    const check = expectCheckFailed(result, 'MCP-010');
    expect(check.severity).toBe('warning');
  });

  it('should produce a low security score', () => {
    const agent = getAgentResult(result, 'mcp');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeLessThan(50);
  });

  it('should assign a failing grade', () => {
    const agent = getAgentResult(result, 'mcp');
    expect(agent).toBeDefined();
    expect(agent!.grade).toBe('F');
  });
});

describe('MCP Secure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/mcp.Dockerfile',
      buildArgs: { SCENARIO: 'secure' },
      command: ['mcp', 'scan', '--path', '/mcp/config.json'],
    });
  });

  it('should detect MCP agent', () => {
    const agent = getAgentResult(result, 'mcp');
    expect(agent).toBeDefined();
  });

  it('should pass transport security check (MCP-002)', () => {
    expectCheckPassed(result, 'MCP-002');
  });

  it('should pass credential exposure check (MCP-003)', () => {
    expectCheckPassed(result, 'MCP-003');
  });

  it('should pass rug pull risk check — pinned versions (MCP-010)', () => {
    expectCheckPassed(result, 'MCP-010');
  });

  it('should produce a high security score', () => {
    const agent = getAgentResult(result, 'mcp');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeGreaterThanOrEqual(90);
  });

  it('should assign a passing grade', () => {
    const agent = getAgentResult(result, 'mcp');
    expect(agent).toBeDefined();
    expect(['A', 'B']).toContain(agent!.grade);
  });
});
