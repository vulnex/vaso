/**
 * Opt-in dependency audit against OSV.dev (`vaso mcp scan --audit-deps`).
 *
 * The bundled advisories cover the MCP SDKs and a handful of popular
 * libraries; OSV covers every npm and PyPI advisory. What leaves the machine:
 * each dependency's registry name and exact version — never code, paths or
 * config. Dependencies known only by a declared range are not sent (OSV needs
 * a version). Results are attached to `ServerDependency.vulnerabilities`, which
 * MCP-027 reports.
 */

import type { Severity } from '../core/types.js';
import { compareVersions } from '../core/semver.js';
import type { MCPServerSource } from './types.js';
import type { DependencyVulnerability, ServerDependency } from './server-dependencies.js';

const OSV_API = 'https://api.osv.dev/v1';
/** querybatch accepts up to 1000 queries per call. */
const BATCH_SIZE = 1000;
const DETAIL_CONCURRENCY = 8;
const DEFAULT_TIMEOUT_MS = 30_000;

type FetchLike = (url: string, init?: { method?: string; body?: string; headers?: Record<string, string>; signal?: AbortSignal }) =>
  Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export interface OsvAuditOptions {
  /** Injectable for hermetic tests; defaults to global fetch. */
  fetch?: FetchLike;
  timeoutMs?: number;
}

export interface OsvAuditSummary {
  /** Distinct name@version pairs sent. */
  queried: number;
  /** Distinct name@version pairs with at least one advisory. */
  vulnerable: number;
  /** Dependencies skipped because only a declared range is known. */
  rangeOnly: number;
  /** Set when OSV could not be reached; the scan continues with bundled advisories only. */
  error?: string;
}

interface OsvVuln {
  id: string;
  summary?: string;
  aliases?: string[];
  database_specific?: { severity?: string };
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ events?: Array<{ introduced?: string; fixed?: string; last_affected?: string }> }>;
  }>;
}

const ECOSYSTEM = { npm: 'npm', pypi: 'PyPI' } as const;

function key(dep: ServerDependency): string {
  return `${dep.ecosystem}:${dep.name}@${dep.version}`;
}

/** GHSA severity → VASO severity; unknown (PYSEC-only, unrated) → warning. */
function mapSeverity(raw: string | undefined): Severity {
  switch (raw?.toUpperCase()) {
    case 'CRITICAL': return 'critical';
    case 'LOW': return 'info';
    default: return 'warning';
  }
}

/** Compare versions, padding PyPI's two-part releases (`5.4` → `5.4.0`). */
function compare(a: string, b: string): number {
  const pad = (v: string) => v.replace(/^(\d+)(?:\.(\d+))?(?=$|[^.\d])/, (_m, x, y = '0') => `${x}.${y}.0`);
  return compareVersions(pad(a), pad(b));
}

/** The lowest fixed release above `version` for this package, if OSV names one. */
function fixedAbove(vuln: OsvVuln, dep: ServerDependency): string | undefined {
  const fixes: string[] = [];
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.ecosystem !== ECOSYSTEM[dep.ecosystem]) continue;
    if (normalize(affected.package?.name ?? '', dep.ecosystem) !== dep.name) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed && compare(event.fixed, dep.version!) > 0) fixes.push(event.fixed);
      }
    }
  }
  return fixes.sort(compare)[0];
}

function normalize(name: string, ecosystem: 'npm' | 'pypi'): string {
  return ecosystem === 'pypi' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name;
}

/**
 * OSV lists one vulnerability under several ids (a GHSA and its PYSEC twin).
 * Keep one entry per alias group, preferring the GHSA (it carries severity).
 */
function dedupe(vulns: OsvVuln[]): OsvVuln[] {
  const kept: OsvVuln[] = [];
  const seen = new Set<string>();
  const ordered = [...vulns].sort((a, b) => Number(!a.id.startsWith('GHSA-')) - Number(!b.id.startsWith('GHSA-')));
  for (const vuln of ordered) {
    const ids = [vuln.id, ...(vuln.aliases ?? [])];
    if (ids.some((id) => seen.has(id))) continue;
    ids.forEach((id) => seen.add(id));
    kept.push(vuln);
  }
  return kept;
}

function toVulnerability(vuln: OsvVuln, dep: ServerDependency): DependencyVulnerability {
  const aliases = (vuln.aliases ?? []).filter((a) => a !== vuln.id);
  const cve = aliases.find((a) => a.startsWith('CVE-'));
  const fixedVersion = fixedAbove(vuln, dep);
  return {
    id: cve ?? vuln.id,
    aliases: [vuln.id, ...aliases].filter((a) => a !== (cve ?? vuln.id)),
    summary: vuln.summary?.trim() || 'Known vulnerability',
    severity: mapSeverity(vuln.database_specific?.severity),
    ...(fixedVersion ? { fixedVersion } : {}),
    reference: `https://osv.dev/vulnerability/${vuln.id}`,
  };
}

async function postJson(fetchImpl: FetchLike, url: string, body: unknown, timeoutMs: number): Promise<unknown> {
  const res = await fetchImpl(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`OSV returned HTTP ${res.status}`);
  return res.json();
}

async function getJson(fetchImpl: FetchLike, url: string, timeoutMs: number): Promise<unknown> {
  const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`OSV returned HTTP ${res.status}`);
  return res.json();
}

export async function auditDependencies(sources: MCPServerSource[], options: OsvAuditOptions = {}): Promise<OsvAuditSummary> {
  const fetchImpl = options.fetch ?? (globalThis.fetch as unknown as FetchLike);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  const byKey = new Map<string, ServerDependency[]>();
  let rangeOnly = 0;
  for (const source of sources) {
    for (const dep of source.dependencies ?? []) {
      if (!dep.version) {
        rangeOnly++;
        continue;
      }
      const list = byKey.get(key(dep)) ?? [];
      list.push(dep);
      byKey.set(key(dep), list);
    }
  }
  const unique = [...byKey.values()].map((deps) => deps[0]);
  const summary: OsvAuditSummary = { queried: unique.length, vulnerable: 0, rangeOnly };
  if (unique.length === 0) return summary;

  try {
    // 1) Which name@version pairs have advisories (ids only).
    const idsByKey = new Map<string, string[]>();
    for (let i = 0; i < unique.length; i += BATCH_SIZE) {
      const batch = unique.slice(i, i + BATCH_SIZE);
      const res = (await postJson(fetchImpl, `${OSV_API}/querybatch`, {
        queries: batch.map((dep) => ({ package: { name: dep.name, ecosystem: ECOSYSTEM[dep.ecosystem] }, version: dep.version })),
      }, timeoutMs)) as { results?: Array<{ vulns?: Array<{ id?: string }> }> };
      batch.forEach((dep, j) => {
        const ids = (res.results?.[j]?.vulns ?? []).map((v) => v.id).filter((id): id is string => typeof id === 'string');
        if (ids.length > 0) idsByKey.set(key(dep), ids);
      });
    }

    // 2) Details for each distinct advisory id.
    const allIds = [...new Set([...idsByKey.values()].flat())];
    const details = new Map<string, OsvVuln>();
    for (let i = 0; i < allIds.length; i += DETAIL_CONCURRENCY) {
      const chunk = allIds.slice(i, i + DETAIL_CONCURRENCY);
      const fetched = await Promise.all(chunk.map((id) => getJson(fetchImpl, `${OSV_API}/vulns/${encodeURIComponent(id)}`, timeoutMs)));
      fetched.forEach((v, j) => details.set(chunk[j], v as OsvVuln));
    }

    for (const [k, ids] of idsByKey) {
      const deps = byKey.get(k)!;
      const vulns = dedupe(ids.map((id) => details.get(id)).filter((v): v is OsvVuln => Boolean(v)));
      if (vulns.length === 0) continue;
      summary.vulnerable++;
      for (const dep of deps) dep.vulnerabilities = vulns.map((v) => toVulnerability(v, dep));
    }
  } catch (err) {
    summary.error = err instanceof Error ? err.message : String(err);
  }
  return summary;
}
