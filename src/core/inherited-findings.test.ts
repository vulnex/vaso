import { describe, it, expect } from 'vitest';
import type { AgentScanResult, CheckResult } from './types.js';
import { dedupeInheritedFindings } from './inherited-findings.js';

const fail = (id: string, evidence?: CheckResult['evidence'], message = `${id} failed`): CheckResult =>
  ({ id, name: id, category: 'config', severity: 'critical', passed: false, message, evidence });

function agent(installDir: string, results: CheckResult[], agentName?: string): AgentScanResult {
  return {
    agent: 'openclaw',
    installation: { agent: 'openclaw', installDir, configFiles: [], agentName },
    results,
    score: 0,
    grade: 'F',
  };
}

describe('dedupeInheritedFindings', () => {
  const shared = { file: '/h/.openclaw/openclaw.json', detail: 'gateway bound to 0.0.0.0' };

  it('marks a sub-agent finding identical to the parent as inherited and rescores', () => {
    const parent = agent('/h/.openclaw', [fail('CFG-001', [shared]), fail('CFG-005')]);
    const sub = agent('/h/.openclaw/agents/main', [fail('CFG-001', [shared]), fail('CFG-005')], 'main');
    dedupeInheritedFindings([parent, sub]);

    expect(sub.results.every(r => r.passed && r.inherited)).toBe(true);
    expect(sub.results[0].message).toContain('/h/.openclaw');
    expect(sub.score).toBe(100);
    expect(parent.results.every(r => !r.passed)).toBe(true);
  });

  it('keeps sub-agent-specific evidence and notes what was shared', () => {
    const own = { file: '/h/.openclaw/agents/main/agent.json', detail: 'sandbox disabled' };
    const parent = agent('/h/.openclaw', [fail('OC-001', [shared])]);
    const sub = agent('/h/.openclaw/agents/main', [fail('OC-001', [shared, own])], 'main');
    dedupeInheritedFindings([parent, sub]);

    expect(sub.results[0].passed).toBe(false);
    expect(sub.results[0].evidence).toEqual([own]);
    expect(sub.results[0].message).toContain('1 shared with');
  });

  it('leaves findings the parent does not have, and unrelated installations, untouched', () => {
    const parent = agent('/h/.openclaw', [fail('CFG-001', [shared])]);
    const sub = agent('/h/.openclaw/agents/main', [fail('SKL-005', [{ file: '/h/.openclaw/agents/main/skills/x.js' }])], 'main');
    const project = agent('/work/app/.openclaw', [fail('CFG-001', [shared])], 'project:app');
    dedupeInheritedFindings([parent, sub, project]);

    expect(sub.results[0].passed).toBe(false);
    expect(project.results[0].passed).toBe(false);
  });
});
