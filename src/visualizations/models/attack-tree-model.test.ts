import { describe, it, expect } from 'vitest';
import { scanResultToAttackTree } from './attack-tree-model.js';
import type { AgentScanResult, CheckResult } from '../../core/types.js';

function checkResult(overrides: Partial<CheckResult>): CheckResult {
  return {
    id: 'X-001',
    name: 'X',
    category: 'config',
    severity: 'warning',
    passed: false,
    message: 'fail',
    ...overrides,
  };
}

function agentScan(overrides: Partial<AgentScanResult> = {}): AgentScanResult {
  return {
    agent: 'openclaw',
    installation: {
      agent: 'openclaw',
      installDir: '/home/u/.openclaw',
      configFiles: [],
    },
    results: [],
    score: 100,
    grade: 'A',
    ...overrides,
  };
}

describe('scanResultToAttackTree', () => {
  it('produces only a root node when there are no failures', () => {
    const tree = scanResultToAttackTree(agentScan());
    expect(tree.nodes).toHaveLength(1);
    expect(tree.nodes[0].kind).toBe('root');
    expect(tree.edges).toEqual([]);
    expect(tree.failedCount).toBe(0);
  });

  it('groups failed findings under category nodes', () => {
    const tree = scanResultToAttackTree(agentScan({
      results: [
        checkResult({ id: 'CFG-001', name: 'Gateway binding', category: 'config', severity: 'critical' }),
        checkResult({ id: 'CFG-005', name: 'Sandbox', category: 'config', severity: 'warning' }),
        checkResult({ id: 'NET-001', name: 'Exposure', category: 'network', severity: 'critical' }),
      ],
    }));
    const categories = tree.nodes.filter(n => n.kind === 'category');
    expect(categories.map(c => c.category).sort()).toEqual(['config', 'network']);
    const findings = tree.nodes.filter(n => n.kind === 'finding');
    expect(findings.map(f => f.id).sort()).toEqual(['CFG-001', 'CFG-005', 'NET-001']);
  });

  it('skips passed checks', () => {
    const tree = scanResultToAttackTree(agentScan({
      results: [
        checkResult({ id: 'A', passed: true }),
        checkResult({ id: 'B', passed: false }),
      ],
    }));
    expect(tree.failedCount).toBe(1);
    expect(tree.nodes.find(n => n.id === 'A')).toBeUndefined();
    expect(tree.nodes.find(n => n.id === 'B')).toBeDefined();
  });

  it('attaches CVSS values to finding nodes', () => {
    const tree = scanResultToAttackTree(agentScan({
      results: [checkResult({ id: 'X', severity: 'critical' })],
    }));
    const finding = tree.nodes.find(n => n.id === 'X');
    expect(finding?.cvss).toBe(9.0);
    expect(finding?.cvssSource).toBe('severity-mapped');
  });

  it('connects root → category → finding via edges', () => {
    const tree = scanResultToAttackTree(agentScan({
      results: [checkResult({ id: 'CFG-001', category: 'config' })],
    }));
    const rootEdge = tree.edges.find(e => e.from === tree.rootId);
    expect(rootEdge?.to).toBe('cat:config');
    const findingEdge = tree.edges.find(e => e.to === 'CFG-001');
    expect(findingEdge?.from).toBe('cat:config');
  });

  it('uses the agent name in the root label when present', () => {
    const tree = scanResultToAttackTree(agentScan({
      installation: {
        agent: 'openclaw',
        agentName: 'workspace',
        installDir: '/x',
        configFiles: [],
      },
      results: [],
    }));
    expect(tree.nodes[0].label).toContain('workspace');
  });
});
