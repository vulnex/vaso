import type { ZoneGraph } from './types.js';

export function defaultZoneGraph(): ZoneGraph {
  return {
    zones: [
      { id: 'net', label: 'Network', trustLevel: 0 },
      { id: 'gw', label: 'Gateway', trustLevel: 1 },
      { id: 'sbx', label: 'Sandbox', trustLevel: 2 },
      { id: 'host', label: 'Host FS', trustLevel: 3 },
    ],
    components: [
      {
        id: 'inbound',
        label: 'Network Ingress',
        zone: 'net',
      },
      {
        id: 'gateway',
        label: 'Agent Gateway',
        zone: 'gw',
        guardCheckIds: ['CFG-001', 'CFG-004', 'NET-001'],
      },
      {
        id: 'sandbox',
        label: 'Sandbox Boundary',
        zone: 'sbx',
        guardCheckIds: ['CFG-005'],
      },
      {
        id: 'fs',
        label: 'Host Filesystem',
        zone: 'host',
        guardCheckIds: ['RUN-001', 'POL-001'],
      },
    ],
    edges: [
      { from: 'inbound', to: 'gateway', kind: 'data' },
      { from: 'gateway', to: 'sandbox', kind: 'control' },
      { from: 'sandbox', to: 'fs', kind: 'data' },
    ],
  };
}
