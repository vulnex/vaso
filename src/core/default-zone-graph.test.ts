import { describe, it, expect } from 'vitest';
import { defaultZoneGraph } from './default-zone-graph.js';
import { validateZoneGraph } from './zone-graph-validator.js';

const REQUIRED_CHECKS = new Set(['CFG-001', 'CFG-004', 'NET-001', 'CFG-005', 'RUN-001', 'POL-001']);

describe('defaultZoneGraph', () => {
  it('builds a 4-zone Network → Gateway → Sandbox → Host FS graph', () => {
    const g = defaultZoneGraph();
    expect(g.zones.map(z => z.id)).toEqual(['net', 'gw', 'sbx', 'host']);
    expect(g.zones.map(z => z.trustLevel)).toEqual([0, 1, 2, 3]);
  });

  it('places one component per zone', () => {
    const g = defaultZoneGraph();
    const zoneToCount = new Map<string, number>();
    for (const c of g.components) zoneToCount.set(c.zone, (zoneToCount.get(c.zone) ?? 0) + 1);
    expect([...zoneToCount.values()]).toEqual([1, 1, 1, 1]);
  });

  it('chains components Network → Gateway → Sandbox → Host FS via edges', () => {
    const g = defaultZoneGraph();
    expect(g.edges).toEqual([
      { from: 'inbound', to: 'gateway', kind: 'data' },
      { from: 'gateway', to: 'sandbox', kind: 'control' },
      { from: 'sandbox', to: 'fs', kind: 'data' },
    ]);
  });

  it('passes the validator when all referenced checks exist', () => {
    expect(validateZoneGraph(defaultZoneGraph(), REQUIRED_CHECKS)).toEqual([]);
  });

  it('only references real check ID prefixes (CFG/NET/RUN/POL)', () => {
    const g = defaultZoneGraph();
    const allRefs = g.components.flatMap(c => c.guardCheckIds ?? []);
    for (const id of allRefs) {
      expect(id).toMatch(/^(CFG|NET|RUN|POL)-\d{3}$/);
    }
  });
});
