import { describe, it, expect } from 'vitest';
import { scanResultToTopology } from './topology-model.js';
import type { ScanResult, AgentScanResult } from '../../core/types.js';

function agentScan(overrides: Partial<AgentScanResult> = {}): AgentScanResult {
  return {
    agent: 'openclaw',
    installation: {
      agent: 'openclaw',
      installDir: '/home/u/.openclaw',
      configFiles: [],
    },
    results: [],
    score: 80,
    grade: 'B',
    ...overrides,
  };
}

function scanResult(overrides: Partial<ScanResult> = {}): ScanResult {
  return {
    timestamp: '2026-04-27T12:00:00Z',
    agents: [],
    totalScore: 80,
    totalGrade: 'B',
    summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
    ...overrides,
  };
}

describe('scanResultToTopology', () => {
  it('produces a host node and one node per agent', () => {
    const topology = scanResultToTopology(scanResult({
      agents: [agentScan({ agent: 'openclaw' }), agentScan({ agent: 'codex' })],
    }));
    const hosts = topology.nodes.filter(n => n.kind === 'host');
    const agents = topology.nodes.filter(n => n.kind === 'agent');
    expect(hosts).toHaveLength(1);
    expect(agents).toHaveLength(2);
  });

  it('connects every agent back to the host', () => {
    const topology = scanResultToTopology(scanResult({
      agents: [agentScan({ agent: 'openclaw' })],
    }));
    const edge = topology.edges.find(e => e.from === topology.hostId);
    expect(edge?.to).toContain('agent:openclaw');
  });

  it('emits a gateway node with TLS label when gateway is present', () => {
    const topology = scanResultToTopology(scanResult({
      agents: [agentScan({
        installation: {
          agent: 'openclaw',
          installDir: '/x',
          configFiles: [],
          gateway: { host: '0.0.0.0', port: 8080, tls: true, authMode: 'token' },
        },
      })],
    }));
    const gateway = topology.nodes.find(n => n.kind === 'gateway');
    expect(gateway?.label).toBe('0.0.0.0:8080');
    expect(gateway?.metadata?.tls).toBe('true');
    const edge = topology.edges.find(e => e.to === gateway?.id);
    expect(edge?.label).toBe('TLS');
  });

  it('labels gateway edge as plain when TLS disabled', () => {
    const topology = scanResultToTopology(scanResult({
      agents: [agentScan({
        installation: {
          agent: 'openclaw',
          installDir: '/x',
          configFiles: [],
          gateway: { host: '127.0.0.1', port: 80, tls: false },
        },
      })],
    }));
    const edge = topology.edges.find(e => e.label === 'plain');
    expect(edge).toBeDefined();
  });

  it('omits the gateway node when no gateway info present', () => {
    const topology = scanResultToTopology(scanResult({
      agents: [agentScan()],
    }));
    expect(topology.nodes.filter(n => n.kind === 'gateway')).toHaveLength(0);
  });

  it('uses provided host label from scan result', () => {
    const topology = scanResultToTopology(scanResult({ host: 'prod-server-01' }));
    expect(topology.hostLabel).toBe('prod-server-01');
  });

  it('falls back to "local host" when no host provided', () => {
    expect(scanResultToTopology(scanResult()).hostLabel).toBe('local host');
  });

  it('preserves scan timestamp', () => {
    const topology = scanResultToTopology(scanResult({ timestamp: '2026-04-27T12:00:00Z' }));
    expect(topology.scanTimestamp).toBe('2026-04-27T12:00:00Z');
  });
});
