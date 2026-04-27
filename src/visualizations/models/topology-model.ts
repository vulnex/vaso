import type { ScanResult, AgentScanResult, AgentType } from '../../core/types.js';

export type TopologyNodeKind = 'agent' | 'gateway' | 'host';

export interface TopologyNode {
  id: string;
  label: string;
  kind: TopologyNodeKind;
  metadata?: Record<string, string>;
}

export interface TopologyEdge {
  from: string;
  to: string;
  label?: string;
}

export interface TopologyModel {
  hostId: string;
  hostLabel: string;
  scanTimestamp: string;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}

export function scanResultToTopology(result: ScanResult): TopologyModel {
  const hostId = 'host';
  const hostLabel = result.host ?? 'local host';

  const nodes: TopologyNode[] = [
    { id: hostId, label: hostLabel, kind: 'host' },
  ];
  const edges: TopologyEdge[] = [];

  for (const agentResult of result.agents) {
    const agentId = agentNodeId(agentResult);
    nodes.push({
      id: agentId,
      label: agentLabel(agentResult),
      kind: 'agent',
      metadata: {
        agent: agentResult.agent,
        score: String(agentResult.score),
        grade: agentResult.grade,
        installDir: agentResult.installation.installDir,
      },
    });
    edges.push({ from: hostId, to: agentId });

    const gw = agentResult.installation.gateway;
    if (gw && (gw.host || gw.port)) {
      const gatewayId = `${agentId}:gateway`;
      const gwLabel = formatGatewayLabel(gw.host, gw.port);
      nodes.push({
        id: gatewayId,
        label: gwLabel,
        kind: 'gateway',
        metadata: {
          tls: gw.tls ? 'true' : 'false',
          authMode: gw.authMode ?? 'unknown',
        },
      });
      edges.push({
        from: agentId,
        to: gatewayId,
        label: gw.tls ? 'TLS' : 'plain',
      });
    }
  }

  return { hostId, hostLabel, scanTimestamp: result.timestamp, nodes, edges };
}

function agentNodeId(agentResult: AgentScanResult): string {
  const slug = (agentResult.installation.installDir ?? agentResult.agent).replace(/[^a-zA-Z0-9]+/g, '_');
  return `agent:${agentResult.agent}:${slug}`;
}

function agentLabel(agentResult: AgentScanResult): string {
  const { agent, installation } = agentResult;
  if (installation.agentName) return `${agent} — ${installation.agentName}`;
  if (installation.user) return `${agent} — ${installation.user}`;
  return agentTypeLabel(agent);
}

function agentTypeLabel(agent: AgentType): string {
  return agent;
}

function formatGatewayLabel(host?: string, port?: number): string {
  if (host && port) return `${host}:${port}`;
  if (host) return host;
  if (port) return `:${port}`;
  return 'gateway';
}
