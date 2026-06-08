import type { CheckModule, OwaspMcpId, ScanResult } from '../core/types.js';

/**
 * OWASP MCP Top 10 (2025) coverage mapping. Single source of truth: maps each
 * MCP-related check ID to the OWASP MCP risk it primarily addresses, so reports
 * can show how VASO's checks line up against the OWASP MCP Top 10.
 *
 * MCP06 (prompt injection) has static coverage for the server-side half —
 * MCP-007 (unsanitized passthrough) and MCP-034 (hardcoded injection directives
 * in tool output); the runtime/contextual half remains an operational concern.
 * MCP08 (audit/telemetry) is intentionally not mapped to a check — it is a
 * runtime/operational concern outside the reach of a static scanner and appears
 * in the coverage table as a gap.
 */

export const OWASP_MCP_TITLES: Record<OwaspMcpId, string> = {
  MCP01: 'Token Mismanagement & Secret Exposure',
  MCP02: 'Privilege Escalation via Scope Creep',
  MCP03: 'Tool Poisoning',
  MCP04: 'Supply Chain & Dependency Tampering',
  MCP05: 'Command Injection & Execution',
  MCP06: 'Prompt Injection via Contextual Payloads',
  MCP07: 'Insufficient Authentication & Authorization',
  MCP08: 'Lack of Audit & Telemetry',
  MCP09: 'Shadow MCP Servers',
  MCP10: 'Context Injection & Over-Sharing',
};

export const CHECK_OWASP_MAP: Record<string, OwaspMcpId> = {
  // Dedicated MCP scanner (mcp category)
  'MCP-001': 'MCP09',
  'MCP-002': 'MCP07',
  'MCP-003': 'MCP01',
  'MCP-004': 'MCP05',
  'MCP-005': 'MCP05',
  'MCP-006': 'MCP10',
  'MCP-007': 'MCP06',
  'MCP-008': 'MCP04',
  'MCP-009': 'MCP02',
  'MCP-010': 'MCP04',
  'MCP-011': 'MCP07',
  'MCP-012': 'MCP01',
  'MCP-013': 'MCP07',
  'MCP-014': 'MCP01',
  'MCP-015': 'MCP07',
  'MCP-016': 'MCP07',
  'MCP-017': 'MCP02',
  'MCP-018': 'MCP07',
  'MCP-019': 'MCP10',
  'MCP-020': 'MCP03',
  'MCP-021': 'MCP05',
  'MCP-022': 'MCP05',
  'MCP-023': 'MCP07',
  'MCP-024': 'MCP03',
  'MCP-025': 'MCP03',
  'MCP-026': 'MCP03',
  'MCP-027': 'MCP04',
  'MCP-028': 'MCP09',
  'MCP-029': 'MCP07',
  'MCP-030': 'MCP04',
  'MCP-031': 'MCP10',
  'MCP-032': 'MCP01',
  'MCP-033': 'MCP01',
  'MCP-034': 'MCP06',
  // Per-agent MCP integration checks
  'CC-005': 'MCP04',
  'CC-006': 'MCP09',
  'CD-003': 'MCP04',
  'CD-004': 'MCP07',
  'CDX-004': 'MCP04',
  'CUR-006': 'MCP07',
  'GEM-007': 'MCP04',
  'GEM-008': 'MCP07',
};

export function owaspMcpForCheckId(id: string): OwaspMcpId | undefined {
  return CHECK_OWASP_MAP[id];
}

/** Populate `owaspMcp` on each check module from the central map (registry
 *  metadata; reporting reads the map directly). */
export function applyOwaspTags(checks: CheckModule[]): void {
  for (const check of checks) {
    const id = CHECK_OWASP_MAP[check.id];
    if (id) check.owaspMcp = id;
  }
}

export interface OwaspMcpCoverageRow {
  id: OwaspMcpId;
  title: string;
  checks: string[]; // check IDs in this result that map to this risk
  failed: number; // how many of those failed
  covered: boolean; // any check present for this risk
}

/**
 * Compute OWASP MCP Top 10 coverage for a scan result: for each of MCP01–10,
 * which checks ran, and how many failed.
 */
export function computeOwaspMcpCoverage(result: ScanResult): OwaspMcpCoverageRow[] {
  const byRisk = new Map<OwaspMcpId, { checks: Set<string>; failed: number }>();
  for (const id of Object.keys(OWASP_MCP_TITLES) as OwaspMcpId[]) {
    byRisk.set(id, { checks: new Set(), failed: 0 });
  }

  for (const agent of result.agents) {
    for (const finding of agent.results) {
      const risk = CHECK_OWASP_MAP[finding.id];
      if (!risk) continue;
      const bucket = byRisk.get(risk)!;
      bucket.checks.add(finding.id);
      if (!finding.passed) bucket.failed += 1;
    }
  }

  return (Object.keys(OWASP_MCP_TITLES) as OwaspMcpId[]).map((id) => {
    const b = byRisk.get(id)!;
    return {
      id,
      title: OWASP_MCP_TITLES[id],
      checks: [...b.checks].sort(),
      failed: b.failed,
      covered: b.checks.size > 0,
    };
  });
}

/** True when the result contains any MCP-mapped findings (i.e. the OWASP MCP
 *  coverage section is worth rendering). */
export function hasOwaspMcpFindings(result: ScanResult): boolean {
  return result.agents.some((a) => a.results.some((r) => CHECK_OWASP_MAP[r.id]));
}

export function renderOwaspMcpCoverageMarkdown(result: ScanResult): string {
  if (!hasOwaspMcpFindings(result)) return '';
  const rows = computeOwaspMcpCoverage(result);
  const lines: string[] = [
    '## OWASP MCP Top 10 Coverage',
    '',
    '| Risk | Title | Checks | Status |',
    '| --- | --- | --- | --- |',
  ];
  for (const row of rows) {
    const status = !row.covered
      ? 'not covered (runtime/operational)'
      : row.failed > 0
        ? `⚠️ ${row.failed} finding(s)`
        : '✅ pass';
    lines.push(`| ${row.id} | ${row.title} | ${row.checks.join(', ') || '—'} | ${status} |`);
  }
  lines.push('');
  return lines.join('\n');
}
