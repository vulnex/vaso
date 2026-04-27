import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { ScanResult, AgentScanResult, ZoneGraph } from '../core/types.js';
import type { AgentAdapter } from '../adapters/adapter.js';
import { defaultZoneGraph } from '../core/default-zone-graph.js';
import { scanResultToAttackTree } from './models/attack-tree-model.js';
import { scanResultToTopology } from './models/topology-model.js';
import {
  attackTreeToUsecvisShape,
  zoneGraphToUsecvisShape,
  topologyToUsecvisShape,
} from './serializers/usecvis-shape.js';
import { serialize, type VisFormat, VIS_FORMAT_EXTENSIONS } from './serializers/format.js';
import { generateBundleReadme } from './readme.js';

export type DiagramKind = 'attack-tree' | 'privilege-gradient' | 'component';

export const ALL_DIAGRAMS: DiagramKind[] = ['attack-tree', 'privilege-gradient', 'component'];

export interface BundleOptions {
  outputDir: string;
  format: VisFormat;
  diagrams: DiagramKind[];
  adapters: ReadonlyMap<string, AgentAdapter>;
}

export interface BundleFile {
  path: string;
  bytes: number;
  diagram: DiagramKind | 'readme';
}

export interface BundleResult {
  outputDir: string;
  format: VisFormat;
  files: BundleFile[];
}

export async function emitBundle(result: ScanResult, options: BundleOptions): Promise<BundleResult> {
  await mkdir(options.outputDir, { recursive: true });

  const files: BundleFile[] = [];
  const ext = VIS_FORMAT_EXTENSIONS[options.format];
  const slugCounts = new Map<string, number>();

  if (options.diagrams.includes('component')) {
    const topology = scanResultToTopology(result);
    const shape = topologyToUsecvisShape(topology);
    const file = await writeBundleFile(options.outputDir, `topology.${ext}`, shape, options.format);
    files.push({ ...file, diagram: 'component' });
  }

  for (const agent of result.agents) {
    const slug = agentSlug(agent, slugCounts);

    if (options.diagrams.includes('attack-tree')) {
      const tree = scanResultToAttackTree(agent);
      const shape = attackTreeToUsecvisShape(tree);
      const file = await writeBundleFile(
        options.outputDir,
        `${slug}-attack-tree.${ext}`,
        shape,
        options.format,
      );
      files.push({ ...file, diagram: 'attack-tree' });
    }

    if (options.diagrams.includes('privilege-gradient')) {
      const graph = resolveZoneGraph(agent, options.adapters);
      const failedCheckIds = new Set(agent.results.filter(r => !r.passed).map(r => r.id));
      const shape = zoneGraphToUsecvisShape(graph, {
        name: `${slug} — Privilege Gradient`,
        description: `Privilege gradient for ${agent.agent} (${failedCheckIds.size} failure${failedCheckIds.size === 1 ? '' : 's'})`,
        failedCheckIds,
      });
      const file = await writeBundleFile(
        options.outputDir,
        `${slug}-privilege-gradient.${ext}`,
        shape,
        options.format,
      );
      files.push({ ...file, diagram: 'privilege-gradient' });
    }
  }

  const readme = generateBundleReadme(result, files, options);
  const readmePath = join(options.outputDir, 'README.md');
  await writeFile(readmePath, readme, 'utf-8');
  files.push({ path: readmePath, bytes: Buffer.byteLength(readme, 'utf-8'), diagram: 'readme' });

  return { outputDir: options.outputDir, format: options.format, files };
}

async function writeBundleFile(
  dir: string,
  filename: string,
  shape: unknown,
  format: VisFormat,
): Promise<{ path: string; bytes: number }> {
  const content = serialize(shape, format);
  const path = join(dir, filename);
  await writeFile(path, content, 'utf-8');
  return { path, bytes: Buffer.byteLength(content, 'utf-8') };
}

function resolveZoneGraph(
  agent: AgentScanResult,
  adapters: ReadonlyMap<string, AgentAdapter>,
): ZoneGraph {
  const adapter = adapters.get(agent.agent);
  return adapter?.getZoneGraph?.() ?? defaultZoneGraph();
}

function agentSlug(agent: AgentScanResult, counts: Map<string, number>): string {
  const base = agent.installation.agentName
    ? `${agent.agent}-${slugify(agent.installation.agentName)}`
    : agent.installation.user
      ? `${agent.agent}-${slugify(agent.installation.user)}`
      : agent.agent;
  const seen = counts.get(base) ?? 0;
  counts.set(base, seen + 1);
  return seen === 0 ? base : `${base}-${seen + 1}`;
}

function slugify(s: string): string {
  return s.replace(/[^a-zA-Z0-9-]+/g, '-').replace(/^-+|-+$/g, '').toLowerCase() || 'unnamed';
}
