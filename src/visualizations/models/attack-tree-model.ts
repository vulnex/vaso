import type { AgentScanResult, AgentType, CheckCategory, CheckResult, Severity } from '../../core/types.js';
import { mapToCvss, type CvssSource } from './cvss-mapper.js';

export interface AttackTreeNode {
  id: string;
  label: string;
  kind: 'root' | 'category' | 'finding';
  category?: CheckCategory;
  severity?: Severity;
  cvss?: number;
  cvssSource?: CvssSource;
}

export interface AttackTreeEdge {
  from: string;
  to: string;
}

export interface AttackTreeModel {
  agent: AgentType;
  agentLabel: string;
  rootId: string;
  nodes: AttackTreeNode[];
  edges: AttackTreeEdge[];
  failedCount: number;
}

const CATEGORY_LABELS: Record<CheckCategory, string> = {
  config: 'Configuration',
  skills: 'Skills',
  ioc: 'Indicators of Compromise',
  network: 'Network',
  runtime: 'Runtime',
  policy: 'Policy',
  mcp: 'MCP',
  openclaw: 'OpenClaw',
  nanoclaw: 'NanoClaw',
  ironclaw: 'IronClaw',
  nanobot: 'Nanobot',
  zeroclaw: 'ZeroClaw',
  lyrie: 'Lyrie',
  advisory: 'Advisories',
  'coding-agent': 'Coding Agent',
};

export function scanResultToAttackTree(agentResult: AgentScanResult): AttackTreeModel {
  const failed = agentResult.results.filter(r => !r.passed);
  const agentLabel = formatAgentLabel(agentResult);
  const rootId = 'root';

  const nodes: AttackTreeNode[] = [
    {
      id: rootId,
      label: `Compromise ${agentLabel}`,
      kind: 'root',
    },
  ];
  const edges: AttackTreeEdge[] = [];

  const byCategory = groupByCategory(failed);
  for (const [category, results] of byCategory) {
    const categoryId = `cat:${category}`;
    nodes.push({
      id: categoryId,
      label: `${CATEGORY_LABELS[category] ?? category} (${results.length})`,
      kind: 'category',
      category,
    });
    edges.push({ from: rootId, to: categoryId });

    for (const r of results) {
      const mapping = mapToCvss(r);
      nodes.push({
        id: r.id,
        label: r.name,
        kind: 'finding',
        category: r.category,
        severity: r.severity,
        cvss: mapping.score,
        cvssSource: mapping.source,
      });
      edges.push({ from: categoryId, to: r.id });
    }
  }

  return {
    agent: agentResult.agent,
    agentLabel,
    rootId,
    nodes,
    edges,
    failedCount: failed.length,
  };
}

function groupByCategory(results: CheckResult[]): Map<CheckCategory, CheckResult[]> {
  const out = new Map<CheckCategory, CheckResult[]>();
  for (const r of results) {
    const arr = out.get(r.category) ?? [];
    arr.push(r);
    out.set(r.category, arr);
  }
  return out;
}

function formatAgentLabel(agentResult: AgentScanResult): string {
  const { agent, installation } = agentResult;
  if (installation.agentName) return `${agent} (${installation.agentName})`;
  if (installation.user) return `${agent} (user: ${installation.user})`;
  return agent;
}
