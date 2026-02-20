import { describe, it, expect } from 'vitest';
import { diffResults } from './baseline.js';
import type { ScanResult, CheckResult, AgentScanResult } from './types.js';

function makeCheckResult(id: string, passed: boolean, severity: 'critical' | 'warning' | 'info' = 'warning'): CheckResult {
  return {
    id,
    name: `Check ${id}`,
    category: 'config',
    severity,
    passed,
    message: passed ? 'OK' : 'Failed',
  };
}

function makeScanResult(checks: CheckResult[]): ScanResult {
  const agent: AgentScanResult = {
    agent: 'openclaw',
    installation: { agent: 'openclaw', installDir: '/tmp', configFiles: [] },
    results: checks,
    score: 100,
    grade: 'A',
  };
  return {
    timestamp: new Date().toISOString(),
    agents: [agent],
    totalScore: 100,
    totalGrade: 'A',
    summary: { critical: 0, warning: 0, info: 0, passed: 0, total: checks.length },
  };
}

describe('diffResults', () => {
  it('detects new findings', () => {
    const baseline = makeScanResult([makeCheckResult('CFG-001', false)]);
    const current = makeScanResult([
      makeCheckResult('CFG-001', false),
      makeCheckResult('CFG-002', false),
    ]);
    const diff = diffResults(current, baseline);
    console.log(`[diffResults] new findings → new: ${diff.newFindings.map(f => f.id)}, unchanged: ${diff.unchangedFindings.map(f => f.id)}, resolved: ${diff.resolvedFindings.map(f => f.id)}`);
    expect(diff.newFindings).toHaveLength(1);
    expect(diff.newFindings[0].id).toBe('CFG-002');
    expect(diff.unchangedFindings).toHaveLength(1);
    expect(diff.resolvedFindings).toHaveLength(0);
  });

  it('detects resolved findings', () => {
    const baseline = makeScanResult([
      makeCheckResult('CFG-001', false),
      makeCheckResult('CFG-002', false),
    ]);
    const current = makeScanResult([makeCheckResult('CFG-001', false)]);
    const diff = diffResults(current, baseline);
    console.log(`[diffResults] resolved findings → new: ${diff.newFindings.map(f => f.id)}, unchanged: ${diff.unchangedFindings.map(f => f.id)}, resolved: ${diff.resolvedFindings.map(f => f.id)}`);
    expect(diff.resolvedFindings).toHaveLength(1);
    expect(diff.resolvedFindings[0].id).toBe('CFG-002');
  });

  it('handles identical results', () => {
    const baseline = makeScanResult([makeCheckResult('CFG-001', false)]);
    const current = makeScanResult([makeCheckResult('CFG-001', false)]);
    const diff = diffResults(current, baseline);
    console.log(`[diffResults] identical → new: ${diff.newFindings.length}, unchanged: ${diff.unchangedFindings.length}, resolved: ${diff.resolvedFindings.length}`);
    expect(diff.newFindings).toHaveLength(0);
    expect(diff.resolvedFindings).toHaveLength(0);
    expect(diff.unchangedFindings).toHaveLength(1);
  });

  it('ignores passed checks', () => {
    const baseline = makeScanResult([makeCheckResult('CFG-001', true)]);
    const current = makeScanResult([makeCheckResult('CFG-001', true)]);
    const diff = diffResults(current, baseline);
    console.log(`[diffResults] all passed → new: ${diff.newFindings.length}, unchanged: ${diff.unchangedFindings.length}, resolved: ${diff.resolvedFindings.length}`);
    expect(diff.newFindings).toHaveLength(0);
    expect(diff.resolvedFindings).toHaveLength(0);
    expect(diff.unchangedFindings).toHaveLength(0);
  });
});
