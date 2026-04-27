import type { ZoneGraph } from '../../core/types.js';
import type { AttackTreeModel, AttackTreeNode } from '../models/attack-tree-model.js';
import type { TopologyModel } from '../models/topology-model.js';

/**
 * Internal models → USecVisLib config-shaped POJOs.
 * Output of these functions is what gets serialized to TOML/JSON/YAML.
 */

export interface UsecvisAttackTreeConfig {
  tree: {
    name: string;
    type: 'Attack Tree';
    description: string;
    root: string;
    version: string;
  };
  nodes: Record<string, NodeAttrs>;
  edges: Record<string, Array<{ to: string; label?: string }>>;
}

interface NodeAttrs {
  style?: string;
  shape?: string;
  fillcolor?: string;
  fontcolor?: string;
  cvss?: number;
}

const ROOT_ATTRS: NodeAttrs = { style: 'filled', shape: 'oval', fillcolor: '#e74c3c', fontcolor: 'white' };
const CATEGORY_ATTRS: NodeAttrs = { style: 'filled', shape: 'box', fillcolor: '#3498db', fontcolor: 'white' };
const FINDING_ATTRS: NodeAttrs = { style: 'filled', shape: 'rectangle' };

export function attackTreeToUsecvisShape(model: AttackTreeModel): UsecvisAttackTreeConfig {
  const labelById = new Map<string, string>();
  for (const n of model.nodes) labelById.set(n.id, n.label);

  const nodes: Record<string, NodeAttrs> = {};
  for (const n of model.nodes) {
    nodes[n.label] = nodeAttrs(n);
  }

  const edges: Record<string, Array<{ to: string; label?: string }>> = {};
  for (const e of model.edges) {
    const fromLabel = labelById.get(e.from);
    const toLabel = labelById.get(e.to);
    if (!fromLabel || !toLabel) continue;
    if (!edges[fromLabel]) edges[fromLabel] = [];
    edges[fromLabel].push({ to: toLabel });
  }

  const rootLabel = labelById.get(model.rootId) ?? `Compromise ${model.agentLabel}`;

  return {
    tree: {
      name: `${model.agentLabel} — Attack Tree`,
      type: 'Attack Tree',
      description: `Failed checks for ${model.agentLabel} (${model.failedCount} finding${model.failedCount === 1 ? '' : 's'})`,
      root: rootLabel,
      version: '1.0',
    },
    nodes,
    edges,
  };
}

function nodeAttrs(n: AttackTreeNode): NodeAttrs {
  if (n.kind === 'root') return { ...ROOT_ATTRS };
  if (n.kind === 'category') return { ...CATEGORY_ATTRS };
  const attrs: NodeAttrs = { ...FINDING_ATTRS };
  if (n.cvss !== undefined) attrs.cvss = n.cvss;
  return attrs;
}

/* Privilege gradient ----------------------------------------------------- */

export interface UsecvisPrivilegeGradientConfig {
  gradient: {
    name: string;
    type: 'Privilege Gradient Graph';
    description: string;
    version: string;
  };
  zones: Array<{ id: string; label: string; trust_level: number }>;
  components: Array<{ id: string; label: string; zone: string; failed?: boolean }>;
  influence_types: Array<{
    id: string;
    label: string;
    color: string;
    style: string;
    arrowhead: string;
    penwidth: string;
  }>;
  influences: Array<{
    id: string;
    from: string;
    to: string;
    type: string;
    label?: string;
    triggered?: boolean;
  }>;
}

export interface ZoneGraphRenderOptions {
  name: string;
  description: string;
  failedCheckIds: ReadonlySet<string>;
}

const INFLUENCE_TYPES: UsecvisPrivilegeGradientConfig['influence_types'] = [
  { id: 'data', label: 'Data Flow', color: '#3498db', style: 'solid', arrowhead: 'vee', penwidth: '1.5' },
  { id: 'control', label: 'Control', color: '#8e44ad', style: 'bold', arrowhead: 'dot', penwidth: '2' },
  { id: 'resource', label: 'Resource', color: '#27ae60', style: 'dotted', arrowhead: 'diamond', penwidth: '2' },
  { id: 'feedback', label: 'Feedback', color: '#e67e22', style: 'dashed', arrowhead: 'vee', penwidth: '1.5' },
];

export function zoneGraphToUsecvisShape(
  graph: ZoneGraph,
  options: ZoneGraphRenderOptions,
): UsecvisPrivilegeGradientConfig {
  const failed = options.failedCheckIds;

  const components = graph.components.map(c => {
    const isFailed = (c.guardCheckIds ?? []).some(id => failed.has(id));
    const out: UsecvisPrivilegeGradientConfig['components'][number] = {
      id: c.id,
      label: c.label,
      zone: c.zone,
    };
    if (isFailed) out.failed = true;
    return out;
  });

  const influences: UsecvisPrivilegeGradientConfig['influences'] = [];
  let i = 0;
  for (const e of graph.edges) {
    const isInversion = e.triggerCheckIds && e.triggerCheckIds.length > 0;
    if (isInversion) {
      const triggered = e.triggerCheckIds!.some(id => failed.has(id));
      if (!triggered) continue;
    }
    influences.push({
      id: `inf_${++i}`,
      from: e.from,
      to: e.to,
      type: e.kind ?? 'data',
      ...(e.label ? { label: e.label } : {}),
      ...(isInversion ? { triggered: true } : {}),
    });
  }

  return {
    gradient: {
      name: options.name,
      type: 'Privilege Gradient Graph',
      description: options.description,
      version: '1.0',
    },
    zones: graph.zones.map(z => ({ id: z.id, label: z.label, trust_level: z.trustLevel })),
    components,
    influence_types: INFLUENCE_TYPES,
    influences,
  };
}

/* Component diagram (topology) ------------------------------------------ */

export interface UsecvisComponentConfig {
  title: string;
  layers: Array<{
    name: string;
    order: number;
    components: Array<{ id: string; name: string; type: string; tech?: string }>;
  }>;
  connections: Array<{ from: string; to: string; label?: string; style: string }>;
}

export function topologyToUsecvisShape(model: TopologyModel): UsecvisComponentConfig {
  const layers: UsecvisComponentConfig['layers'] = [
    { name: 'Host', order: 1, components: [] },
    { name: 'Agents', order: 2, components: [] },
    { name: 'Network', order: 3, components: [] },
  ];

  for (const n of model.nodes) {
    if (n.kind === 'host') {
      layers[0].components.push({ id: n.id, name: n.label, type: 'storage' });
    } else if (n.kind === 'agent') {
      layers[1].components.push({
        id: n.id,
        name: n.label,
        type: 'cli',
        ...(n.metadata?.installDir ? { tech: n.metadata.installDir } : {}),
      });
    } else if (n.kind === 'gateway') {
      layers[2].components.push({
        id: n.id,
        name: n.label,
        type: 'service',
        ...(n.metadata?.tls ? { tech: n.metadata.tls === 'true' ? 'TLS' : 'plain' } : {}),
      });
    }
  }

  const connections: UsecvisComponentConfig['connections'] = model.edges.map(e => ({
    from: e.from,
    to: e.to,
    ...(e.label ? { label: e.label } : {}),
    style: 'sync',
  }));

  return {
    title: `VASO Scan Topology — ${model.hostLabel}`,
    layers,
    connections,
  };
}
