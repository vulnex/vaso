import { describe, it, expect } from 'vitest';
import { JsonReporter } from './json.js';
import type { ScanResult } from '../core/types.js';

function makeScanResult(overrides?: Partial<ScanResult>): ScanResult {
  return {
    timestamp: '2026-02-21T12:00:00.000Z',
    agents: [{
      agent: 'openclaw',
      installation: {
        agent: 'openclaw',
        installDir: '/home/user/.openclaw',
        configFiles: [],
        user: 'testuser',
        profile: 'default',
      },
      results: [
        {
          id: 'CFG-001',
          name: 'Gateway Binding',
          category: 'config',
          severity: 'critical',
          passed: false,
          message: 'Gateway bound to 0.0.0.0',
          evidence: [{ file: '/home/user/.openclaw/config.yaml', line: 12 }],
          fixable: true,
          fixDescription: 'Bind to 127.0.0.1',
        },
        {
          id: 'CFG-002',
          name: 'API Key Exposure',
          category: 'config',
          severity: 'critical',
          passed: true,
          message: 'No API keys found in config',
        },
      ],
      score: 65,
      grade: 'C',
    }],
    totalScore: 65,
    totalGrade: 'C',
    fleetAverage: 65,
    summary: { critical: 1, warning: 0, info: 0, passed: 1, total: 2 },
    ...overrides,
  };
}

describe('JsonReporter', () => {
  it('has format property set to json', () => {
    const reporter = new JsonReporter();
    expect(reporter.format).toBe('json');
  });

  it('produces valid JSON', () => {
    const reporter = new JsonReporter();
    const output = reporter.render(makeScanResult());
    expect(() => JSON.parse(output)).not.toThrow();
  });

  it('uses 2-space indentation', () => {
    const reporter = new JsonReporter();
    const output = reporter.render(makeScanResult());
    // Second line should start with 2 spaces (not tab or 4 spaces)
    const lines = output.split('\n');
    expect(lines[1]).toMatch(/^  "/);
  });

  it('preserves all fields in round-trip', () => {
    const reporter = new JsonReporter();
    const input = makeScanResult();
    const output = reporter.render(input);
    const parsed = JSON.parse(output);

    expect(parsed.timestamp).toBe(input.timestamp);
    expect(parsed.totalScore).toBe(input.totalScore);
    expect(parsed.totalGrade).toBe(input.totalGrade);
    expect(parsed.agents).toHaveLength(1);
    expect(parsed.agents[0].agent).toBe('openclaw');
    expect(parsed.agents[0].results).toHaveLength(2);
    expect(parsed.agents[0].results[0].id).toBe('CFG-001');
    expect(parsed.agents[0].results[0].evidence).toHaveLength(1);
    expect(parsed.summary).toEqual(input.summary);
  });

  it('handles empty agents array', () => {
    const reporter = new JsonReporter();
    const output = reporter.render(makeScanResult({
      agents: [],
      totalScore: 100,
      totalGrade: 'A',
      fleetAverage: 100,
      summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
    }));
    const parsed = JSON.parse(output);
    expect(parsed.agents).toEqual([]);
    expect(parsed.totalScore).toBe(100);
  });
});
