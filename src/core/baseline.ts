import { readFile, mkdir, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { ScanResult, CheckResult } from './types.js';
import { writeFileOwnerOnly } from './utils.js';
import { toReportJson } from '../reporting/serialize.js';

const BASELINES_DIR = join(homedir(), '.vaso', 'baselines');

export interface DiffResult {
  newFindings: CheckResult[];
  resolvedFindings: CheckResult[];
  unchangedFindings: CheckResult[];
}

/**
 * What a baseline was taken of: every agent on this machine (`all`), or one
 * agent (`-a`) and/or another host (snapshot / remote). Each scope keeps its
 * own "latest", so `--save-baseline -a hermes` followed by `--diff -a abacus`
 * no longer compares two different scans. The default scope keeps the
 * historic `latest.json` name.
 */
export interface BaselineScope {
  agent?: string;
  host?: string;
}

function latestName(scope: BaselineScope = {}): string {
  const parts = [scope.agent, scope.host].filter((p): p is string => Boolean(p))
    .map(p => p.replace(/[^A-Za-z0-9._-]/g, '_'));
  return parts.length === 0 ? 'latest.json' : `latest-${parts.join('--')}.json`;
}

export async function saveBaseline(result: ScanResult, scope: BaselineScope = {}): Promise<string> {
  // Scan history is private: owner-only dir and files, config contents stripped
  await mkdir(BASELINES_DIR, { recursive: true, mode: 0o700 });
  await chmod(BASELINES_DIR, 0o700);
  const filename = `baseline-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
  const filePath = join(BASELINES_DIR, filename);
  const json = toReportJson(result);
  await writeFileOwnerOnly(filePath, json);

  // Also save as this scope's "latest"
  const latestPath = join(BASELINES_DIR, latestName(scope));
  await writeFileOwnerOnly(latestPath, json);

  return filePath;
}

export async function loadBaseline(scope: BaselineScope = {}): Promise<ScanResult | null> {
  const latestPath = join(BASELINES_DIR, latestName(scope));
  try {
    const content = await readFile(latestPath, 'utf-8');
    return JSON.parse(content) as ScanResult;
  } catch {
    return null;
  }
}

function installationKey(agent: ScanResult['agents'][number]): string {
  const inst = agent.installation;
  return [
    agent.agent,
    inst.user ?? '',
    inst.profile ?? '',
    inst.agentName ?? '',
    inst.installDir,
  ].join(':');
}

/**
 * Where a finding is, not how it is worded: the files its evidence names.
 * Detail text, snippets and line numbers change with VASO's wording and with
 * unrelated edits to the file, and made the same finding show as both new
 * and resolved.
 */
function evidenceKey(finding: CheckResult): string {
  if (!finding.evidence || finding.evidence.length === 0) return '';
  return [...new Set(finding.evidence.filter(e => !e.mitigated).map(e => e.file ?? ''))]
    .sort()
    .join('|');
}

function findingKey(agent: ScanResult['agents'][number], finding: CheckResult): string {
  return `${installationKey(agent)}:${finding.id}:${evidenceKey(finding)}`;
}

export function diffResults(current: ScanResult, baseline: ScanResult): DiffResult {
  const currentFindings = new Map<string, CheckResult>();
  const baselineFindings = new Map<string, CheckResult>();

  for (const agent of current.agents) {
    for (const r of agent.results) {
      if (!r.passed) currentFindings.set(findingKey(agent, r), r);
    }
  }

  for (const agent of baseline.agents) {
    for (const r of agent.results) {
      if (!r.passed) baselineFindings.set(findingKey(agent, r), r);
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
