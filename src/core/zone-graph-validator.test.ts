import { describe, it, expect } from 'vitest';
import {
  validateZoneGraph,
  validateAllZoneGraphs,
  assertZoneGraphsValid,
  ZoneGraphValidationFailedError,
} from './zone-graph-validator.js';
import { defaultZoneGraph } from './default-zone-graph.js';
import { CheckRegistry } from './check-registry.js';
import { AdapterRegistry } from '../adapters/registry.js';
import type { ZoneGraph, CheckModule, ScanContext, CheckResult } from './types.js';
import type { AgentAdapter } from '../adapters/adapter.js';

function mockCheck(id: string): CheckModule {
  return {
    id,
    name: id,
    category: 'config',
    severity: 'warning',
    description: 'mock',
    async run(_ctx: ScanContext): Promise<CheckResult> {
      return { id, name: id, category: 'config', severity: 'warning', passed: true, message: 'ok' };
    },
  };
}

function mockAdapter(graph?: ZoneGraph): AgentAdapter {
  return {
    agent: 'openclaw',
    displayName: 'Mock',
    async detect() { return []; },
    getConfigPaths() { return []; },
    getSkillsDir() { return undefined; },
    getGatewayInfo() { return undefined; },
    getZoneGraph: graph ? () => graph : undefined,
  };
}

const ALL_CHECKS = new Set(['CHK-A', 'CHK-B', 'CHK-C']);

describe('validateZoneGraph', () => {
  it('accepts a minimal valid graph', () => {
    const graph: ZoneGraph = {
      zones: [
        { id: 'z0', label: 'Z0', trustLevel: 0 },
        { id: 'z1', label: 'Z1', trustLevel: 1 },
      ],
      components: [
        { id: 'a', label: 'A', zone: 'z0' },
        { id: 'b', label: 'B', zone: 'z1', guardCheckIds: ['CHK-A'] },
      ],
      edges: [{ from: 'a', to: 'b', kind: 'data' }],
    };
    expect(validateZoneGraph(graph, ALL_CHECKS)).toEqual([]);
  });

  it('flags component referencing unknown zone', () => {
    const graph: ZoneGraph = {
      zones: [{ id: 'z0', label: 'Z0', trustLevel: 0 }],
      components: [{ id: 'a', label: 'A', zone: 'missing' }],
      edges: [],
    };
    const errors = validateZoneGraph(graph, ALL_CHECKS);
    expect(errors).toHaveLength(1);
    expect(errors[0].rule).toBe('component-zone-exists');
  });

  it('flags edge with unknown endpoint', () => {
    const graph: ZoneGraph = {
      zones: [{ id: 'z0', label: 'Z0', trustLevel: 0 }],
      components: [{ id: 'a', label: 'A', zone: 'z0' }],
      edges: [{ from: 'a', to: 'ghost' }],
    };
    const errors = validateZoneGraph(graph, ALL_CHECKS);
    expect(errors.some(e => e.rule === 'edge-endpoint-exists')).toBe(true);
  });

  it('flags unknown check IDs in component guards', () => {
    const graph: ZoneGraph = {
      zones: [{ id: 'z0', label: 'Z0', trustLevel: 0 }],
      components: [{ id: 'a', label: 'A', zone: 'z0', guardCheckIds: ['UNKNOWN'] }],
      edges: [],
    };
    const errors = validateZoneGraph(graph, ALL_CHECKS);
    expect(errors).toHaveLength(1);
    expect(errors[0].rule).toBe('check-id-registered');
    expect(errors[0].detail).toContain('UNKNOWN');
  });

  it('flags unknown check IDs in edge triggers', () => {
    const graph: ZoneGraph = {
      zones: [
        { id: 'z0', label: 'Z0', trustLevel: 0 },
        { id: 'z1', label: 'Z1', trustLevel: 1 },
      ],
      components: [
        { id: 'a', label: 'A', zone: 'z0' },
        { id: 'b', label: 'B', zone: 'z1' },
      ],
      edges: [{ from: 'a', to: 'b', triggerCheckIds: ['UNKNOWN'] }],
    };
    const errors = validateZoneGraph(graph, ALL_CHECKS);
    expect(errors.some(e => e.rule === 'check-id-registered' && e.detail.includes('UNKNOWN'))).toBe(true);
  });

  it('flags duplicate trust levels', () => {
    const graph: ZoneGraph = {
      zones: [
        { id: 'z0', label: 'Z0', trustLevel: 0 },
        { id: 'z1', label: 'Z1', trustLevel: 0 },
      ],
      components: [],
      edges: [],
    };
    const errors = validateZoneGraph(graph, ALL_CHECKS);
    expect(errors.some(e => e.rule === 'zone-trust-level-unique')).toBe(true);
  });

  it('flags inversion edge with no triggerCheckIds', () => {
    const graph: ZoneGraph = {
      zones: [
        { id: 'z0', label: 'Z0', trustLevel: 0 },
        { id: 'z1', label: 'Z1', trustLevel: 1 },
        { id: 'z2', label: 'Z2', trustLevel: 2 },
      ],
      components: [
        { id: 'low', label: 'Low', zone: 'z0' },
        { id: 'high', label: 'High', zone: 'z2' },
      ],
      edges: [{ from: 'low', to: 'high', kind: 'data' }],
    };
    const errors = validateZoneGraph(graph, ALL_CHECKS);
    expect(errors.some(e => e.rule === 'inversion-requires-trigger')).toBe(true);
  });

  it('accepts inversion edge with triggerCheckIds', () => {
    const graph: ZoneGraph = {
      zones: [
        { id: 'z0', label: 'Z0', trustLevel: 0 },
        { id: 'z2', label: 'Z2', trustLevel: 2 },
      ],
      components: [
        { id: 'low', label: 'Low', zone: 'z0' },
        { id: 'high', label: 'High', zone: 'z2' },
      ],
      edges: [{ from: 'low', to: 'high', triggerCheckIds: ['CHK-A'] }],
    };
    expect(validateZoneGraph(graph, ALL_CHECKS)).toEqual([]);
  });

  it('does not flag adjacent-zone edges as inversions', () => {
    const graph: ZoneGraph = {
      zones: [
        { id: 'z0', label: 'Z0', trustLevel: 0 },
        { id: 'z1', label: 'Z1', trustLevel: 1 },
      ],
      components: [
        { id: 'a', label: 'A', zone: 'z0' },
        { id: 'b', label: 'B', zone: 'z1' },
      ],
      edges: [{ from: 'a', to: 'b' }],
    };
    expect(validateZoneGraph(graph, ALL_CHECKS)).toEqual([]);
  });

  it('flags empty zone id', () => {
    const graph: ZoneGraph = {
      zones: [{ id: '', label: 'Empty', trustLevel: 0 }],
      components: [],
      edges: [],
    };
    const errors = validateZoneGraph(graph, ALL_CHECKS);
    expect(errors.some(e => e.rule === 'zone-id-nonempty')).toBe(true);
  });
});

describe('validateAllZoneGraphs', () => {
  it('uses the fallback for adapters without getZoneGraph', () => {
    const adapters = new AdapterRegistry();
    adapters.register(mockAdapter());
    const checks = new CheckRegistry();
    checks.register(mockCheck('CHK-A'));
    const errors = validateAllZoneGraphs(
      adapters,
      checks,
      () => ({
        zones: [{ id: 'z0', label: 'Z0', trustLevel: 0 }],
        components: [{ id: 'a', label: 'A', zone: 'z0', guardCheckIds: ['CHK-A'] }],
        edges: [],
      }),
    );
    expect(errors).toEqual([]);
  });

  it('reports errors with the adapter name attached', () => {
    const adapters = new AdapterRegistry();
    const adapter = mockAdapter({
      zones: [{ id: 'z0', label: 'Z0', trustLevel: 0 }],
      components: [{ id: 'a', label: 'A', zone: 'ghost' }],
      edges: [],
    });
    adapters.register(adapter);
    const errors = validateAllZoneGraphs(adapters, new CheckRegistry(), defaultZoneGraph);
    expect(errors).toHaveLength(1);
    expect(errors[0].adapter).toBe('openclaw');
  });
});

describe('assertZoneGraphsValid', () => {
  it('throws ZoneGraphValidationFailedError when invalid', () => {
    const adapters = new AdapterRegistry();
    adapters.register(mockAdapter({
      zones: [{ id: 'z0', label: 'Z0', trustLevel: 0 }],
      components: [{ id: 'a', label: 'A', zone: 'ghost' }],
      edges: [],
    }));
    expect(() =>
      assertZoneGraphsValid(adapters, new CheckRegistry(), defaultZoneGraph),
    ).toThrow(ZoneGraphValidationFailedError);
  });

  it('does not throw when all graphs valid', () => {
    const adapters = new AdapterRegistry();
    adapters.register(mockAdapter());
    const checks = new CheckRegistry();
    for (const id of ['CFG-001', 'CFG-004', 'NET-001', 'CFG-005', 'RUN-001', 'POL-001']) {
      checks.register(mockCheck(id));
    }
    expect(() => assertZoneGraphsValid(adapters, checks, defaultZoneGraph)).not.toThrow();
  });
});
