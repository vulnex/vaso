import { describe, it, expect } from 'vitest';
import {
  attackTreeToUsecvisShape,
  zoneGraphToUsecvisShape,
  topologyToUsecvisShape,
} from './usecvis-shape.js';
import type { AttackTreeModel } from '../models/attack-tree-model.js';
import type { TopologyModel } from '../models/topology-model.js';
import type { ZoneGraph } from '../../core/types.js';

describe('attackTreeToUsecvisShape', () => {
  const tree: AttackTreeModel = {
    agent: 'openclaw',
    agentLabel: 'openclaw',
    rootId: 'root',
    failedCount: 1,
    nodes: [
      { id: 'root', label: 'Compromise openclaw', kind: 'root' },
      { id: 'cat:config', label: 'Configuration (1)', kind: 'category', category: 'config' },
      { id: 'CFG-001', label: 'Gateway Binding', kind: 'finding', category: 'config', severity: 'critical', cvss: 9.0, cvssSource: 'severity-mapped' },
    ],
    edges: [
      { from: 'root', to: 'cat:config' },
      { from: 'cat:config', to: 'CFG-001' },
    ],
  };

  it('builds a [tree] section with the root label', () => {
    const shape = attackTreeToUsecvisShape(tree);
    expect(shape.tree.type).toBe('Attack Tree');
    expect(shape.tree.root).toBe('Compromise openclaw');
  });

  it('emits one node entry per model node, keyed by label', () => {
    const shape = attackTreeToUsecvisShape(tree);
    expect(shape.nodes['Compromise openclaw'].shape).toBe('oval');
    expect(shape.nodes['Configuration (1)'].shape).toBe('box');
    expect(shape.nodes['Gateway Binding'].shape).toBe('rectangle');
  });

  it('preserves CVSS on finding nodes', () => {
    const shape = attackTreeToUsecvisShape(tree);
    expect(shape.nodes['Gateway Binding'].cvss).toBe(9.0);
  });

  it('builds adjacency edges keyed by from-label', () => {
    const shape = attackTreeToUsecvisShape(tree);
    expect(shape.edges['Compromise openclaw']).toEqual([{ to: 'Configuration (1)' }]);
    expect(shape.edges['Configuration (1)']).toEqual([{ to: 'Gateway Binding' }]);
  });
});

describe('zoneGraphToUsecvisShape', () => {
  const graph: ZoneGraph = {
    zones: [
      { id: 'z0', label: 'Net', trustLevel: 0 },
      { id: 'z1', label: 'GW', trustLevel: 1 },
      { id: 'z2', label: 'Host', trustLevel: 2 },
    ],
    components: [
      { id: 'in', label: 'Inbound', zone: 'z0' },
      { id: 'gw', label: 'Gateway', zone: 'z1', guardCheckIds: ['CFG-001'] },
      { id: 'fs', label: 'FS', zone: 'z2', guardCheckIds: ['POL-001'] },
    ],
    edges: [
      { from: 'in', to: 'gw', kind: 'data' },
      { from: 'gw', to: 'fs', kind: 'control' },
      { from: 'in', to: 'fs', label: 'bypass', triggerCheckIds: ['CFG-001'] },
    ],
  };

  it('emits zones with snake_case trust_level', () => {
    const shape = zoneGraphToUsecvisShape(graph, {
      name: 'x', description: 'y', failedCheckIds: new Set(),
    });
    expect(shape.zones[0]).toEqual({ id: 'z0', label: 'Net', trust_level: 0 });
  });

  it('marks components as failed when any guard check fails', () => {
    const shape = zoneGraphToUsecvisShape(graph, {
      name: 'x', description: 'y', failedCheckIds: new Set(['CFG-001']),
    });
    const gw = shape.components.find(c => c.id === 'gw');
    expect(gw?.failed).toBe(true);
    const fs = shape.components.find(c => c.id === 'fs');
    expect(fs?.failed).toBeUndefined();
  });

  it('omits non-triggered inversion edges', () => {
    const shape = zoneGraphToUsecvisShape(graph, {
      name: 'x', description: 'y', failedCheckIds: new Set(),
    });
    const inversion = shape.influences.find(i => i.label === 'bypass');
    expect(inversion).toBeUndefined();
    expect(shape.influences).toHaveLength(2);
  });

  it('includes triggered inversion edges with triggered=true', () => {
    const shape = zoneGraphToUsecvisShape(graph, {
      name: 'x', description: 'y', failedCheckIds: new Set(['CFG-001']),
    });
    const inversion = shape.influences.find(i => i.label === 'bypass');
    expect(inversion).toBeDefined();
    expect(inversion?.triggered).toBe(true);
  });

  it('emits the four standard influence_types', () => {
    const shape = zoneGraphToUsecvisShape(graph, {
      name: 'x', description: 'y', failedCheckIds: new Set(),
    });
    expect(shape.influence_types.map(t => t.id)).toEqual(['data', 'control', 'resource', 'feedback']);
  });
});

describe('topologyToUsecvisShape', () => {
  const model: TopologyModel = {
    hostId: 'host',
    hostLabel: 'local host',
    scanTimestamp: '2026-04-27T12:00:00Z',
    nodes: [
      { id: 'host', label: 'local host', kind: 'host' },
      { id: 'agent:openclaw:_x', label: 'openclaw', kind: 'agent', metadata: { installDir: '/x' } },
      { id: 'agent:openclaw:_x:gateway', label: '0.0.0.0:8080', kind: 'gateway', metadata: { tls: 'true' } },
    ],
    edges: [
      { from: 'host', to: 'agent:openclaw:_x' },
      { from: 'agent:openclaw:_x', to: 'agent:openclaw:_x:gateway', label: 'TLS' },
    ],
  };

  it('places host/agent/gateway nodes into ordered layers', () => {
    const shape = topologyToUsecvisShape(model);
    expect(shape.layers.map(l => l.name)).toEqual(['Host', 'Agents', 'Network']);
    expect(shape.layers[0].components).toHaveLength(1);
    expect(shape.layers[1].components).toHaveLength(1);
    expect(shape.layers[2].components).toHaveLength(1);
  });

  it('preserves edges as connections with sync style', () => {
    const shape = topologyToUsecvisShape(model);
    expect(shape.connections).toHaveLength(2);
    expect(shape.connections[1].label).toBe('TLS');
    expect(shape.connections[0].style).toBe('sync');
  });

  it('uses host label in title', () => {
    const shape = topologyToUsecvisShape(model);
    expect(shape.title).toContain('local host');
  });
});
