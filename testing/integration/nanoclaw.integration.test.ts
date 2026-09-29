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

  it('should detect the NanoClaw v2 checkout with its package.json version', () => {
    const agent = getAgentResult(result, 'nanoclaw');
    expect(agent).toBeDefined();
    expect(agent!.installation.installDir).toBe('/root/nanoclaw');
    expect(agent!.installation.version).toBe('2.4.0');
    expect(agent!.installation.configFiles.map(c => c.filePath)).toEqual([
      '/root/nanoclaw/.env',
      '/root/.config/nanoclaw/mount-allowlist.json',
    ]);
  });

  it('should detect home/filesystem allowedRoots (NC-001)', () => {
    const check = expectCheckFailed(result, 'NC-001');
    expect(check.severity).toBe('critical');
  });

  it('should detect a world-writable mount allowlist (NC-002)', () => {
    const check = expectCheckFailed(result, 'NC-002');
    expect(check.severity).toBe('critical');
  });

  it('should detect a world-writable checkout / data dir (NC-003)', () => {
    const check = expectCheckFailed(result, 'NC-003');
    expect(check.severity).toBe('critical');
  });

  it('should detect the Slack webhook listener on 0.0.0.0 (NC-004)', () => {
    const check = expectCheckFailed(result, 'NC-004');
    expect(check.severity).toBe('warning');
  });

  it('should detect a world-writable container/skills dir (NC-005)', () => {
    const check = expectCheckFailed(result, 'NC-005');
    expect(check.severity).toBe('warning');
  });

  it('should detect a world-readable .env (CFG-003)', () => {
    expectCheckFailed(result, 'CFG-003');
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

  it('should pass every NanoClaw check', () => {
    for (const id of ['NC-001', 'NC-002', 'NC-003', 'NC-004', 'NC-005']) {
      expectCheckPassed(result, id);
    }
  });

  it('should pass credential permissions (CFG-003)', () => {
    expectCheckPassed(result, 'CFG-003');
  });

  it('should produce a high security score', () => {
    const agent = getAgentResult(result, 'nanoclaw');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeGreaterThanOrEqual(75);
  });
});
