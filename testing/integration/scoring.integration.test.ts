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
    it('should have a total score of 90 or above', () => {
      expect(secureResult.totalScore).toBeGreaterThanOrEqual(90);
    });

    it('should have a passing grade (A or B)', () => {
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
    it('should average scores across agents when multiple exist', async () => {
      const multiResult = await runVasoScan({
        dockerfile: 'testing/docker/agents/multi.Dockerfile',
        buildArgs: { SCENARIO: 'insecure' },
      });

      const agentScores = multiResult.agents.map(a => a.score);
      const expectedTotal = Math.round(
        agentScores.reduce((sum, s) => sum + s, 0) / agentScores.length
      );
      expect(multiResult.totalScore).toBe(expectedTotal);
    });
  });
});
