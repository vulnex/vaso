import { describe, it, expect, beforeAll } from 'vitest';
import type { ScanResult } from '../../src/core/types.js';
import { runVasoScan, getAgentResult } from './helpers.js';

describe('End-to-End Scoring Validation', () => {
  let insecureResult: ScanResult;
  let secureResult: ScanResult;

  beforeAll(async () => {
    [insecureResult, secureResult] = await Promise.all([
      runVasoScan({
        dockerfile: 'testing/docker/agents/openclaw.Dockerfile',
        buildArgs: { SCENARIO: 'insecure' },
      }),
      runVasoScan({
        dockerfile: 'testing/docker/agents/openclaw.Dockerfile',
        buildArgs: { SCENARIO: 'secure' },
      }),
    ]);
  });

  describe('Insecure environment scoring', () => {
    it('should have a total score below 50', () => {
      expect(insecureResult.totalScore).toBeLessThan(50);
    });

    it('should have a failing grade (D or F)', () => {
      expect(['D', 'F']).toContain(insecureResult.totalGrade);
    });

    it('should have multiple critical findings', () => {
      expect(insecureResult.summary.critical).toBeGreaterThanOrEqual(5);
    });

    it('should have warning findings', () => {
      expect(insecureResult.summary.warning).toBeGreaterThan(0);
    });

    it('should have the correct total count', () => {
      const expectedTotal =
        insecureResult.summary.critical +
        insecureResult.summary.warning +
        insecureResult.summary.info +
        insecureResult.summary.passed;
      expect(insecureResult.summary.total).toBe(expectedTotal);
    });
  });

  describe('Secure environment scoring', () => {
    it('should score every agent well in the secure scenario', () => {
      // The secure scenario provisions OpenClaw *and* a NemoClaw sandbox layer
      // (so CFG-016–019 pass — see openclaw.Dockerfile). The headline score is
      // worst-case across agents, so assert each detected agent scores well
      // rather than the blended total, which the previous `>= 90` check assumed
      // was a mean.
      for (const agent of secureResult.agents) {
        expect(agent.score, `${agent.agent} score`).toBeGreaterThanOrEqual(80);
        expect(['A', 'B'], `${agent.agent} grade`).toContain(agent.grade);
      }
    });

    it('should have a passing headline grade (A or B)', () => {
      // Worst-case headline: gated by the weakest secure agent, still a B or better.
      expect(secureResult.totalScore).toBeGreaterThanOrEqual(80);
      expect(['A', 'B']).toContain(secureResult.totalGrade);
    });

    it('should have zero critical findings', () => {
      expect(secureResult.summary.critical).toBe(0);
    });

    it('should have more passed checks than failed', () => {
      const failed = secureResult.summary.critical + secureResult.summary.warning;
      expect(secureResult.summary.passed).toBeGreaterThan(failed);
    });
  });

  describe('Score penalty math', () => {
    it('should apply -12 per critical failure', () => {
      const agent = getAgentResult(insecureResult, 'openclaw')!;
      const criticalFails = agent.results.filter(r => !r.passed && r.severity === 'critical').length;
      const warningFails = agent.results.filter(r => !r.passed && r.severity === 'warning').length;

      // Score = max(0, 100 - 12*criticals - 5*warnings)
      const expectedScore = Math.max(0, Math.min(100, 100 - (criticalFails * 12) - (warningFails * 5)));
      expect(agent.score).toBe(expectedScore);
    });

    it('should clamp score to 0 minimum', () => {
      const agent = getAgentResult(insecureResult, 'openclaw')!;
      expect(agent.score).toBeGreaterThanOrEqual(0);
    });

    it('should assign correct grade based on score', () => {
      const agent = getAgentResult(insecureResult, 'openclaw')!;
      if (agent.score >= 90) expect(agent.grade).toBe('A');
      else if (agent.score >= 80) expect(agent.grade).toBe('B');
      else if (agent.score >= 70) expect(agent.grade).toBe('C');
      else if (agent.score >= 60) expect(agent.grade).toBe('D');
      else expect(agent.grade).toBe('F');
    });
  });

  describe('Overall score aggregation', () => {
    it('should report worst-case (minimum) as the headline and the mean as fleetAverage', async () => {
      const multiResult = await runVasoScan({
        dockerfile: 'testing/docker/agents/multi.Dockerfile',
        buildArgs: { SCENARIO: 'insecure' },
      });

      const agentScores = multiResult.agents.map(a => a.score);
      // Headline is the weakest agent — a secure posture is gated by its worst
      // agent, and a mean would let clean agents mask a wide-open one.
      expect(multiResult.totalScore).toBe(Math.min(...agentScores));
      // The mean is preserved as a secondary fleet-health metric.
      const expectedMean = Math.round(
        agentScores.reduce((sum, s) => sum + s, 0) / agentScores.length
      );
      expect(multiResult.fleetAverage).toBe(expectedMean);
    });
  });
});
