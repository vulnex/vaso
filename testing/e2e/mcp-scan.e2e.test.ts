import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { resolve, join } from 'node:path';
import { mkdtemp, rm, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { generateMCPConfig } from './helpers/mcp-config.js';
import { runVasoJSON } from './helpers/cli-runner.js';
import type { ScanResult } from '../../src/core/types.js';

const PROJECT_ROOT = resolve(import.meta.dirname, '../..');
const VULNERABLE_SERVER = join(
  PROJECT_ROOT,
  'testing/fixtures/mcp/mcp-server-source/vulnerable-server/index.js',
);

function findCheck(result: ScanResult, checkId: string) {
  for (const agent of result.agents) {
    const check = agent.results.find(r => r.id === checkId);
    if (check) return check;
  }
  return undefined;
}

function getAgentResult(result: ScanResult, agent: string) {
  return result.agents.find(a => a.agent === agent);
}

describe('E2E: vaso mcp scan — insecure config', () => {
  let tempDir: string;
  let configPath: string;
  let result: ScanResult;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-e2e-mcp-'));
    configPath = join(tempDir, 'claude_desktop_config.json');

    await generateMCPConfig(configPath, {
      includeInsecure: true,
      vulnerableServerPath: VULNERABLE_SERVER,
    });

    result = await runVasoJSON(
      ['mcp', 'scan', '--path', configPath],
      { HOME: tempDir },
    );
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('should detect MCP agent', () => {
    const agent = getAgentResult(result, 'mcp');
    expect(agent).toBeDefined();
    expect(agent!.agent).toBe('mcp');
  });

  it('should detect insecure SSE transport (MCP-002)', () => {
    const check = findCheck(result, 'MCP-002');
    expect(check).toBeDefined();
    expect(check!.passed).toBe(false);
    expect(check!.severity).toBe('critical');
  });

  it('should detect plaintext credentials (MCP-003)', () => {
    const check = findCheck(result, 'MCP-003');
    expect(check).toBeDefined();
    expect(check!.passed).toBe(false);
    expect(check!.severity).toBe('critical');
  });

  it('should detect exec/eval in vulnerable server source (MCP-004)', () => {
    const check = findCheck(result, 'MCP-004');
    expect(check).toBeDefined();
    expect(check!.passed).toBe(false);
  });

  it('should detect unsanitized input injection (MCP-005)', () => {
    const check = findCheck(result, 'MCP-005');
    expect(check).toBeDefined();
    expect(check!.passed).toBe(false);
  });

  it('should detect data exfiltration risk (MCP-006)', () => {
    const check = findCheck(result, 'MCP-006');
    expect(check).toBeDefined();
    expect(check!.passed).toBe(false);
  });

  it('should produce a low security score', () => {
    const agent = getAgentResult(result, 'mcp');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeLessThan(50);
  });
});

describe('E2E: vaso mcp scan — clean config (real packages only)', () => {
  let tempDir: string;
  let configPath: string;
  let result: ScanResult;

  beforeAll(async () => {
    tempDir = await mkdtemp(join(tmpdir(), 'vaso-e2e-mcp-'));
    configPath = join(tempDir, 'claude_desktop_config.json');

    // Only real, clean MCP packages — no insecure entries
    await generateMCPConfig(configPath, {
      includeInsecure: false,
    });

    // Create .vaso dirs to suppress warnings
    await mkdir(join(tempDir, '.vaso/ioc'), { recursive: true });

    result = await runVasoJSON(
      ['mcp', 'scan', '--path', configPath],
      { HOME: tempDir },
    );
  });

  afterAll(async () => {
    await rm(tempDir, { recursive: true, force: true });
  });

  it('should produce a higher score than insecure config', () => {
    const agent = getAgentResult(result, 'mcp');
    expect(agent).toBeDefined();
    expect(agent!.score).toBeGreaterThanOrEqual(70);
  });
});
