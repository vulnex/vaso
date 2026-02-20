import { describe, it, expect, beforeAll } from 'vitest';
import type { ScanResult } from '../../src/core/types.js';
import { runVasoScan, getAgentResult } from './helpers.js';

describe('Multi-Agent Detection', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/multi.Dockerfile',
      buildArgs: { SCENARIO: 'insecure' },
    });
  });

  it('should detect all three agents', () => {
    expect(result.agents).toHaveLength(3);

    const agentNames = result.agents.map(a => a.agent).sort();
    expect(agentNames).toEqual(['nanoclaw', 'openclaw', 'picoclaw']);
  });

  it('should detect OpenClaw', () => {
    const agent = getAgentResult(result, 'openclaw');
    expect(agent).toBeDefined();
    expect(agent!.results.length).toBeGreaterThan(0);
  });

  it('should detect NanoClaw', () => {
    const agent = getAgentResult(result, 'nanoclaw');
    expect(agent).toBeDefined();
    expect(agent!.results.length).toBeGreaterThan(0);
  });

  it('should detect PicoClaw', () => {
    const agent = getAgentResult(result, 'picoclaw');
    expect(agent).toBeDefined();
    expect(agent!.results.length).toBeGreaterThan(0);
  });

  it('should run checks independently per agent', () => {
    const openclaw = getAgentResult(result, 'openclaw')!;
    const nanoclaw = getAgentResult(result, 'nanoclaw')!;
    const picoclaw = getAgentResult(result, 'picoclaw')!;

    // Each agent should have its own score
    expect(openclaw.score).toBeDefined();
    expect(nanoclaw.score).toBeDefined();
    expect(picoclaw.score).toBeDefined();

    // Each agent should have its own grade
    expect(openclaw.grade).toBeDefined();
    expect(nanoclaw.grade).toBeDefined();
    expect(picoclaw.grade).toBeDefined();
  });

  it('should compute an overall total score', () => {
    expect(result.totalScore).toBeDefined();
    expect(result.totalScore).toBeGreaterThanOrEqual(0);
    expect(result.totalScore).toBeLessThanOrEqual(100);
  });

  it('should compute summary statistics across all agents', () => {
    expect(result.summary).toBeDefined();
    expect(result.summary.critical).toBeGreaterThan(0);
    expect(result.summary.total).toBeGreaterThan(0);
  });
});

describe('Multi-Agent Agent Filter', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/multi.Dockerfile',
      buildArgs: { SCENARIO: 'insecure' },
      env: { VASO_AGENT_FILTER: 'openclaw' },
    });
  });

  // Note: The --agent filter is a CLI option, not env var.
  // This test validates the multi-agent container works.
  // Agent filtering is tested via the CLI directly in other tests.
  it('should produce valid scan results', () => {
    expect(result).toBeDefined();
    expect(result.agents.length).toBeGreaterThan(0);
    expect(result.timestamp).toBeDefined();
  });
});

describe('Multi-Agent Secure', () => {
  let result: ScanResult;

  beforeAll(async () => {
    result = await runVasoScan({
      dockerfile: 'testing/docker/agents/multi.Dockerfile',
      buildArgs: { SCENARIO: 'secure' },
    });
  });

  it('should detect all three agents in secure mode', () => {
    expect(result.agents).toHaveLength(3);
  });

  it('should produce high scores for all agents', () => {
    for (const agent of result.agents) {
      expect(agent.score).toBeGreaterThanOrEqual(80);
    }
  });

  it('should have no critical findings', () => {
    expect(result.summary.critical).toBe(0);
  });
});
