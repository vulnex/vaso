import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { ScanResult, CheckResult } from './types.js';

const BASELINES_DIR = join(homedir(), '.vaso', 'baselines');

export interface DiffResult {
  newFindings: CheckResult[];
  resolvedFindings: CheckResult[];
  unchangedFindings: CheckResult[];
}

export async function saveBaseline(result: ScanResult): Promise<string> {
  await mkdir(BASELINES_DIR, { recursive: true });
  const filename = `baseline-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
  const filePath = join(BASELINES_DIR, filename);
  await writeFile(filePath, JSON.stringify(result, null, 2), 'utf-8');

  // Also save as "latest"
  const latestPath = join(BASELINES_DIR, 'latest.json');
  await writeFile(latestPath, JSON.stringify(result, null, 2), 'utf-8');

  return filePath;
}

export async function loadBaseline(): Promise<ScanResult | null> {
  const latestPath = join(BASELINES_DIR, 'latest.json');
  try {
    const content = await readFile(latestPath, 'utf-8');
    return JSON.parse(content) as ScanResult;
  } catch {
    return null;
  }
}

export function diffResults(current: ScanResult, baseline: ScanResult): DiffResult {
  const currentFindings = new Map<string, CheckResult>();
  const baselineFindings = new Map<string, CheckResult>();

  for (const agent of current.agents) {
    for (const r of agent.results) {
      if (!r.passed) currentFindings.set(`${agent.agent}:${r.id}`, r);
    }
  }

  for (const agent of baseline.agents) {
    for (const r of agent.results) {
      if (!r.passed) baselineFindings.set(`${agent.agent}:${r.id}`, r);
    }
  }

  const newFindings: CheckResult[] = [];
  const resolvedFindings: CheckResult[] = [];
  const unchangedFindings: CheckResult[] = [];

  for (const [key, finding] of currentFindings) {
    if (baselineFindings.has(key)) {
      unchangedFindings.push(finding);
    } else {
      newFindings.push(finding);
    }
  }

  for (const [key, finding] of baselineFindings) {
    if (!currentFindings.has(key)) {
      resolvedFindings.push(finding);
    }
  }

  return { newFindings, resolvedFindings, unchangedFindings };
}
