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

async function readBaseline(name: string): Promise<ScanResult | null> {
  try {
    return JSON.parse(await readFile(join(BASELINES_DIR, name), 'utf-8')) as ScanResult;
  } catch {
    return null;
  }
}

export async function loadBaseline(scope: BaselineScope = {}): Promise<ScanResult | null> {
  const scoped = await readBaseline(latestName(scope));
  if (scoped || latestName(scope) === 'latest.json') return scoped;
  // Before 1.3.1 every baseline was saved as latest.json, whatever its
  // scope. Use one that covers exactly this scope — same scanned host, only
  // the filtered agent — so an upgrade doesn't lose `--diff` history.
  const legacy = await readBaseline('latest.json');
  if (!legacy || legacy.vasoVersion !== undefined) return null;
  if ((legacy.host ?? undefined) !== (scope.host ?? undefined)) return null;
  if (scope.agent && !(legacy.agents.length > 0 && legacy.agents.every(a => a.agent === scope.agent))) return null;
  return legacy;
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
 * Where a repeated finding is, not how it is worded: the files its evidence names.
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

/**
 * A check reports one result per installation, so a failing check is the
 * same finding in both scans while its evidence names only files it already
 * named (losing one keeps it unchanged). Naming a file the baseline didn't
 * — a secret leaked into a new file — makes it new; moving wholly to other
 * files also resolves the old one. Ids that repeat within an installation
 * (CONFIG-LOAD, one per unreadable file) are told apart by their exact file
 * set.
 */
function findingKey(agent: ScanResult['agents'][number], finding: CheckResult, repeated: Set<string>): string {
  const base = `${installationKey(agent)}:${finding.id}`;
  return repeated.has(base) ? `${base}:${evidenceKey(finding)}` : base;
}

/** `installation:id` keys that occur more than once in an installation of either scan. */
function repeatedIds(...scans: ScanResult[]): Set<string> {
  const repeated = new Set<string>();
  for (const scan of scans) {
    for (const agent of scan.agents) {
      const seen = new Set<string>();
      for (const r of agent.results) {
        const base = `${installationKey(agent)}:${r.id}`;
        if (seen.has(base)) repeated.add(base);
        seen.add(base);
      }
    }
  }
  return repeated;
}

function evidenceFiles(f: CheckResult): string[] {
  return evidenceKey(f).split('|').filter(Boolean);
}

/** Still the baseline's finding: names no file the baseline's didn't (both naming none counts). */
function sameFinding(now: CheckResult, before: CheckResult): boolean {
  const old = new Set(evidenceFiles(before));
  const files = evidenceFiles(now);
  if (files.length === 0 || old.size === 0) return files.length === 0 && old.size === 0;
  return files.every(f => old.has(f));
}

/** The baseline's finding is still reported: a current finding under its key names one of its files. */
function stillReported(before: CheckResult, now: CheckResult | undefined): boolean {
  if (!now) return false;
  const files = new Set(evidenceFiles(now));
  const old = evidenceFiles(before);
  if (old.length === 0 || files.size === 0) return old.length === 0 && files.size === 0;
  return old.some(f => files.has(f));
}

export function diffResults(current: ScanResult, baseline: ScanResult): DiffResult {
  const currentFindings = new Map<string, CheckResult>();
  const baselineFindings = new Map<string, CheckResult>();
  const repeated = repeatedIds(current, baseline);

  for (const agent of current.agents) {
    for (const r of agent.results) {
      if (!r.passed) currentFindings.set(findingKey(agent, r, repeated), r);
    }
  }

  for (const agent of baseline.agents) {
    for (const r of agent.results) {
      if (!r.passed) baselineFindings.set(findingKey(agent, r, repeated), r);
    }
  }

  const newFindings: CheckResult[] = [];
  const resolvedFindings: CheckResult[] = [];
  const unchangedFindings: CheckResult[] = [];

  for (const [key, finding] of currentFindings) {
    const before = baselineFindings.get(key);
    if (before && sameFinding(finding, before)) {
      unchangedFindings.push(finding);
    } else {
      newFindings.push(finding);
    }
  }

  for (const [key, finding] of baselineFindings) {
    if (!stillReported(finding, currentFindings.get(key))) {
      resolvedFindings.push(finding);
    }
  }

  return { newFindings, resolvedFindings, unchangedFindings };
}
