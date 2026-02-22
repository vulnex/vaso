import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createE2EEnvironment, type E2EEnvironment } from './helpers/setup.js';
import { runVasoJSON } from './helpers/cli-runner.js';
import type { ScanResult, AgentScanResult } from '../../src/core/types.js';

function getAgentResult(result: ScanResult, agent: string): AgentScanResult | undefined {
  return result.agents.find(a => a.agent === agent);
}

function findCheck(result: ScanResult, checkId: string) {
  for (const agent of result.agents) {
    const check = agent.results.find(r => r.id === checkId);
    if (check) return check;
  }
  return undefined;
}

describe('E2E: vaso scan — all agents insecure', () => {
  let env: E2EEnvironment;
  let result: ScanResult;

  beforeAll(async () => {
    env = await createE2EEnvironment({ scenario: 'insecure' });
    result = await runVasoJSON(['scan'], { HOME: env.tempHome });
  });

  afterAll(async () => {
    await env.cleanup();
  });

  it('should find all 6 agents', () => {
    const agentTypes = result.agents.map(a => a.agent);
    expect(agentTypes).toContain('openclaw');
    expect(agentTypes).toContain('nanoclaw');
    expect(agentTypes).toContain('picoclaw');
    expect(agentTypes).toContain('ironclaw');
    expect(agentTypes).toContain('nanobot');
    expect(agentTypes).toContain('zeroclaw');
  });

  it('should have check results for each agent', () => {
    for (const agent of result.agents) {
      expect(agent.results.length).toBeGreaterThan(0);
    }
  });

  it('should detect CFG-001 — gateway binding', () => {
    const check = findCheck(result, 'CFG-001');
    expect(check).toBeDefined();
    expect(check!.passed).toBe(false);
  });

  it('should detect CFG-008 — sandbox disabled', () => {
    const check = findCheck(result, 'CFG-008');
    expect(check).toBeDefined();
    expect(check!.passed).toBe(false);
  });

  it('should detect IronClaw-specific IC-005 — sandbox policy', () => {
    const ironclaw = getAgentResult(result, 'ironclaw');
    expect(ironclaw).toBeDefined();
    const check = ironclaw!.results.find(r => r.id === 'IC-005');
    expect(check).toBeDefined();
    expect(check!.passed).toBe(false);
  });

  it('should run Nanobot-specific checks', () => {
    const nanobot = getAgentResult(result, 'nanobot');
    expect(nanobot).toBeDefined();
    expect(nanobot!.results.length).toBeGreaterThan(0);
  });

  it('should detect ZeroClaw-specific ZC-001 — plaintext keys', () => {
    const zeroclaw = getAgentResult(result, 'zeroclaw');
    expect(zeroclaw).toBeDefined();
    const check = zeroclaw!.results.find(r => r.id === 'ZC-001');
    expect(check).toBeDefined();
    expect(check!.passed).toBe(false);
  });

  it('should have a total score and grade', () => {
    expect(result.totalScore).toBeDefined();
    expect(result.totalScore).toBeGreaterThanOrEqual(0);
    expect(result.totalScore).toBeLessThanOrEqual(100);
    expect(result.totalGrade).toBeDefined();
  });

  it('should produce a low score for insecure configs', () => {
    expect(result.totalScore).toBeLessThan(50);
    expect(result.totalGrade).toBe('F');
  });
});

describe('E2E: vaso scan — agent filter', () => {
  let env: E2EEnvironment;
  let result: ScanResult;

  beforeAll(async () => {
    env = await createE2EEnvironment({ scenario: 'insecure' });
    result = await runVasoJSON(
      ['scan', '--agent', 'openclaw'],
      { HOME: env.tempHome },
    );
  });

  afterAll(async () => {
    await env.cleanup();
  });

  it('should only return OpenClaw results', () => {
    expect(result.agents.length).toBeGreaterThanOrEqual(1);
    for (const agent of result.agents) {
      expect(agent.agent).toBe('openclaw');
    }
  });
});

describe('E2E: vaso scan — secure scenario', () => {
  let env: E2EEnvironment;
  let result: ScanResult;

  beforeAll(async () => {
    env = await createE2EEnvironment({
      agents: ['openclaw'],
      scenario: 'secure',
      configPermissions: 0o600,
    });
    result = await runVasoJSON(['scan'], { HOME: env.tempHome });
  });

  afterAll(async () => {
    await env.cleanup();
  });

  it('should produce a higher score for secure config', () => {
    // Local e2e may score lower than Docker integration tests due to
    // environment differences (e.g., missing CLI binaries, macOS permissions).
    // Secure config should still score >= 65 (passing threshold).
    expect(result.totalScore).toBeGreaterThanOrEqual(65);
  });

  it('should assign a passing grade', () => {
    expect(['A', 'B', 'C']).toContain(result.totalGrade);
  });
});

describe('E2E: vaso scan — insecure vs secure comparison', () => {
  let insecureEnv: E2EEnvironment;
  let secureEnv: E2EEnvironment;
  let insecureResult: ScanResult;
  let secureResult: ScanResult;

  beforeAll(async () => {
    [insecureEnv, secureEnv] = await Promise.all([
      createE2EEnvironment({
        agents: ['openclaw'],
        scenario: 'insecure',
      }),
      createE2EEnvironment({
        agents: ['openclaw'],
        scenario: 'secure',
        configPermissions: 0o600,
      }),
    ]);

    [insecureResult, secureResult] = await Promise.all([
      runVasoJSON(['scan'], { HOME: insecureEnv.tempHome }),
      runVasoJSON(['scan'], { HOME: secureEnv.tempHome }),
    ]);
  });

  afterAll(async () => {
    await Promise.all([insecureEnv.cleanup(), secureEnv.cleanup()]);
  });

  it('insecure score should be < 50 (grade F)', () => {
    expect(insecureResult.totalScore).toBeLessThan(50);
    expect(insecureResult.totalGrade).toBe('F');
  });

  it('secure score should be >= 65', () => {
    expect(secureResult.totalScore).toBeGreaterThanOrEqual(65);
  });

  it('secure score should be significantly higher', () => {
    expect(secureResult.totalScore).toBeGreaterThan(insecureResult.totalScore + 30);
  });
});
