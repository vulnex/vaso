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

  it('should produce a low score for each insecure agent', () => {
    // Assert on the installed fixture agents, not the blended `totalScore`.
    // `vaso scan` (no --agent) also auto-detects real agents installed on the
    // host via system paths / PATH binaries outside the temp HOME (e.g.
    // /Applications/ChatGPT.app, the `codex`/`claude` CLIs), each scoring ~100.
    // Those would dilute `totalScore` on a developer machine (passing only on a
    // clean CI runner), so per-agent assertions keep this host-independent.
    for (const agentType of ['openclaw', 'nanoclaw', 'picoclaw', 'ironclaw', 'nanobot', 'zeroclaw']) {
      const agent = getAgentResult(result, agentType);
      expect(agent, `${agentType} should be detected`).toBeDefined();
      expect(agent!.score, `${agentType} score`).toBeLessThan(50);
      expect(agent!.grade, `${agentType} grade`).toBe('F');
    }
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
    // Per-agent (not blended totalScore) so the result doesn't depend on which
    // real agents happen to be installed on the host — see the insecure block.
    // Local e2e may score lower than Docker integration tests due to
    // environment differences (e.g., missing CLI binaries, macOS permissions).
    // Secure config should still score >= 65 (passing threshold).
    const openclaw = getAgentResult(result, 'openclaw');
    expect(openclaw).toBeDefined();
    expect(openclaw!.score).toBeGreaterThanOrEqual(65);
  });

  it('should assign a passing grade', () => {
    const openclaw = getAgentResult(result, 'openclaw');
    expect(openclaw).toBeDefined();
    expect(['A', 'B', 'C']).toContain(openclaw!.grade);
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

  // Compare the openclaw agent's own score across scenarios, not the blended
  // totalScore — `vaso scan` also detects real host-installed agents (~100
  // each) that would otherwise pull the insecure average up on a dev machine.
  it('insecure score should be < 50 (grade F)', () => {
    const openclaw = getAgentResult(insecureResult, 'openclaw');
    expect(openclaw).toBeDefined();
    expect(openclaw!.score).toBeLessThan(50);
    expect(openclaw!.grade).toBe('F');
  });

  it('secure score should be >= 65', () => {
    const openclaw = getAgentResult(secureResult, 'openclaw');
    expect(openclaw).toBeDefined();
    expect(openclaw!.score).toBeGreaterThanOrEqual(65);
  });

  it('secure score should be significantly higher', () => {
    const insecure = getAgentResult(insecureResult, 'openclaw');
    const secure = getAgentResult(secureResult, 'openclaw');
    expect(insecure).toBeDefined();
    expect(secure).toBeDefined();
    expect(secure!.score).toBeGreaterThan(insecure!.score + 30);
  });
});
