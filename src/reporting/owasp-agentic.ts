import type { CheckModule, OwaspAgenticId, ScanResult } from '../core/types.js';

/**
 * OWASP Agentic AI Top 10 coverage mapping (precize list:
 * https://github.com/precize/Agentic-AI-Top10-Vulnerability). Single source of
 * truth: maps each check ID to the Agentic AI risk(s) it addresses, so reports
 * can show how VASO's checks line up against the Agentic AI Top 10.
 *
 * Unlike the OWASP MCP map, a check may map to MORE THAN ONE risk — many posture
 * findings touch two risks at once (e.g. a YOLO/auto-approve setting both grants
 * unchecked authority (AAI001) and removes the approval checker (AAI012)). Values
 * are therefore arrays, ordered most-relevant first.
 *
 * The list omits deprecated entries (AAI004 Hallucination, AAI008 Resource
 * Exhaustion — folded into AAI005, AAI010 Knowledge Base Poisoning — folded into
 * AAI006) and in-development entries (AAI013/015/016).
 *
 * Coverage strength varies sharply across two risks:
 *  - AAI011 (Untraceability) has THIN static coverage — only checks that disable
 *    audit/telemetry config (POL-002, CG-003, OPC-004, QC-009, CUR-007/010); the
 *    runtime audit-trail concern is mostly out of a static scanner's reach, but
 *    it is partially in the catalog, so it is not a full gap.
 *  - AAI014 (Alignment Faking) is purely behavioral/runtime — no static signal,
 *    so NO check maps to it. It is the only true catalog gap and always renders
 *    as "not covered (runtime/behavioral)".
 *
 * A handful of checks have no clean Agentic-Top-10 home and are deliberately
 * left out of the map: pure secret-confidentiality / PII at rest (CG-001 world-
 * readable workspace data, CG-002 plaintext account email) — secret exposure is
 * an LLM-Top-10 / general-AppSec concern the Agentic list does not enumerate —
 * and SKL-012 (cyclomatic-complexity metric, no direct security risk).
 */

export const OWASP_AGENTIC_TITLES: Record<OwaspAgenticId, string> = {
  AAI001: 'Agent Authorization and Control Hijacking',
  AAI002: 'Agent Critical Systems Interaction',
  AAI003: 'Agent Goal and Instruction Manipulation',
  AAI005: 'Agent Impact Chain and Blast Radius',
  AAI006: 'Agent Memory and Context Manipulation',
  AAI007: 'Agent Orchestration and Multi-Agent Exploitation',
  AAI009: 'Agent Supply Chain and Dependency Attacks',
  AAI011: 'Agent Untraceability',
  AAI012: 'Agent Checker out of the Loop',
  AAI014: 'Agent Alignment Faking',
};

export const CHECK_AGENTIC_MAP: Record<string, OwaspAgenticId[]> = {
  // Dedicated MCP scanner (mcp category)
  'MCP-001': ['AAI007'],
  'MCP-002': ['AAI009', 'AAI001'],
  'MCP-003': ['AAI001'],
  'MCP-004': ['AAI002', 'AAI005'],
  'MCP-005': ['AAI002', 'AAI003'],
  'MCP-006': ['AAI005'],
  'MCP-007': ['AAI003'],
  'MCP-008': ['AAI009'],
  'MCP-009': ['AAI001', 'AAI005'],
  'MCP-010': ['AAI009', 'AAI006'],
  'MCP-011': ['AAI001', 'AAI009'],
  'MCP-012': ['AAI001'],
  'MCP-013': ['AAI001'],
  'MCP-014': ['AAI001'],
  'MCP-015': ['AAI001'],
  'MCP-016': ['AAI001'],
  'MCP-017': ['AAI001', 'AAI005'],
  'MCP-018': ['AAI001'],
  'MCP-019': ['AAI003', 'AAI005'],
  'MCP-020': ['AAI006', 'AAI003'],
  'MCP-021': ['AAI002', 'AAI005'],
  'MCP-022': ['AAI002', 'AAI005', 'AAI009'],
  'MCP-023': ['AAI001', 'AAI005'],
  'MCP-024': ['AAI003'],
  'MCP-025': ['AAI007'],
  'MCP-026': ['AAI007'],
  'MCP-027': ['AAI009'],
  'MCP-028': ['AAI006', 'AAI009'],
  'MCP-029': ['AAI001'],
  'MCP-030': ['AAI009'],
  'MCP-031': ['AAI005', 'AAI002'],
  'MCP-032': ['AAI005', 'AAI002'],
  'MCP-033': ['AAI001'],
  'MCP-034': ['AAI003'],
  'MCP-035': ['AAI009'],
  // Server config (CFG)
  'CFG-001': ['AAI005'],
  'CFG-002': ['AAI001'],
  'CFG-003': ['AAI001'],
  'CFG-004': ['AAI005'],
  'CFG-005': ['AAI002', 'AAI001'],
  'CFG-006': ['AAI002', 'AAI005'],
  'CFG-007': ['AAI001', 'AAI005'],
  'CFG-008': ['AAI002', 'AAI005'],
  'CFG-009': ['AAI001'],
  'CFG-010': ['AAI005'],
  'CFG-011': ['AAI009'],
  'CFG-012': ['AAI001', 'AAI005'],
  'CFG-013': ['AAI001', 'AAI005'],
  'CFG-014': ['AAI001', 'AAI012'],
  'CFG-015': ['AAI005'],
  'CFG-016': ['AAI002', 'AAI005'],
  'CFG-017': ['AAI002', 'AAI005'],
  'CFG-018': ['AAI005'],
  'CFG-019': ['AAI009'],
  'CFG-020': ['AAI001'],
  'CFG-021': ['AAI002', 'AAI005'],
  'CFG-022': ['AAI002', 'AAI005'],
  'CFG-023': ['AAI009'],
  'CFG-024': ['AAI002', 'AAI005'],
  // Network exposure (NET)
  'NET-001': ['AAI005'],
  'NET-002': ['AAI001', 'AAI005'],
  'NET-003': ['AAI001', 'AAI005'],
  'NET-004': ['AAI005'],
  'NET-005': ['AAI005'],
  // Runtime (RUN)
  'RUN-001': ['AAI002', 'AAI005'],
  'RUN-002': ['AAI002', 'AAI005'],
  'RUN-003': ['AAI009'],
  'RUN-004': ['AAI002', 'AAI005'],
  'RUN-005': ['AAI002'],
  // Policy (POL)
  'POL-001': ['AAI012', 'AAI001'],
  'POL-002': ['AAI011'],
  'POL-003': ['AAI001'],
  'POL-004': ['AAI002', 'AAI005'],
  'POL-005': ['AAI001'],
  // Skills code analysis (SKL)
  'SKL-001': ['AAI005', 'AAI002'],
  'SKL-002': ['AAI009', 'AAI002'],
  'SKL-003': ['AAI002'],
  'SKL-004': ['AAI002', 'AAI009'],
  'SKL-005': ['AAI002', 'AAI005'],
  'SKL-006': ['AAI002', 'AAI005'],
  'SKL-007': ['AAI003'],
  'SKL-008': ['AAI005', 'AAI002'],
  'SKL-009': ['AAI002', 'AAI005'],
  'SKL-010': ['AAI002'],
  'SKL-011': ['AAI009'],
  'SKL-013': ['AAI002', 'AAI012', 'AAI005'],
  // Indicators of compromise (IOC)
  'IOC-001': ['AAI009', 'AAI005'],
  'IOC-002': ['AAI009', 'AAI005'],
  'IOC-003': ['AAI009'],
  'IOC-004': ['AAI009'],
  'IOC-005': ['AAI009'],
  'IOC-006': ['AAI009'],
  'IOC-007': ['AAI009', 'AAI002'],
  'IOC-008': ['AAI009'],
  // Advisory / known-CVE (ADV)
  'ADV-001': ['AAI009'],
  'ADV-002': ['AAI009'],
  'ADV-003': ['AAI009'],
  'ADV-004': ['AAI009'],
  'ADV-005': ['AAI009'],
  // OpenClaw (OC)
  'OC-001': ['AAI007', 'AAI001'],
  'OC-003': ['AAI001'],
  'OC-004': ['AAI005', 'AAI001'],
  'OC-005': ['AAI001'],
  'OC-006': ['AAI006'],
  'OC-007': ['AAI001', 'AAI002'],
  // NanoClaw (NC)
  'NC-001': ['AAI002', 'AAI005'],
  'NC-002': ['AAI001', 'AAI002'],
  'NC-003': ['AAI005', 'AAI002'],
  'NC-004': ['AAI005'],
  'NC-005': ['AAI002', 'AAI009'],
  // IronClaw (IC)
  'IC-001': ['AAI005'],
  'IC-002': ['AAI005'],
  'IC-003': ['AAI005'],
  'IC-004': ['AAI001'],
  'IC-005': ['AAI002', 'AAI005'],
  'IC-006': ['AAI002', 'AAI005'],
  'IC-007': ['AAI012', 'AAI001'],
  'IC-008': ['AAI002', 'AAI005'],
  'IC-009': ['AAI001', 'AAI005'],
  'IC-010': ['AAI001'],
  'IC-011': ['AAI005'],
  'IC-012': ['AAI009'],
  // Nanobot (NB)
  'NB-001': ['AAI001'],
  'NB-002': ['AAI001'],
  'NB-003': ['AAI002', 'AAI005'],
  'NB-004': ['AAI002'],
  'NB-005': ['AAI005'],
  'NB-006': ['AAI003', 'AAI006'],
  'NB-007': ['AAI003', 'AAI006'],
  'NB-008': ['AAI001'],
  'NB-009': ['AAI006'],
  'NB-010': ['AAI005', 'AAI001'],
  'NB-011': ['AAI005'],
  'NB-012': ['AAI009'],
  // ZeroClaw (ZC)
  'ZC-001': ['AAI001'],
  'ZC-002': ['AAI001'],
  'ZC-003': ['AAI005'],
  'ZC-004': ['AAI001'],
  'ZC-005': ['AAI012', 'AAI001'],
  'ZC-006': ['AAI002', 'AAI005'],
  'ZC-007': ['AAI001'],
  'ZC-008': ['AAI009'],
  'ZC-009': ['AAI001'],
  'ZC-010': ['AAI005', 'AAI009'],
  'ZC-011': ['AAI005'],
  'ZC-012': ['AAI005'],
  'ZC-013': ['AAI001'],
  'ZC-014': ['AAI002', 'AAI005'],
  // Lyrie (LY)
  'LY-001': ['AAI012', 'AAI002'],
  'LY-002': ['AAI012', 'AAI002'],
  'LY-003': ['AAI001', 'AAI003'],
  'LY-004': ['AAI001'],
  'LY-005': ['AAI012'],
  'LY-006': ['AAI001'],
  'LY-007': ['AAI001'],
  'LY-008': ['AAI001', 'AAI005'],
  'LY-009': ['AAI012'],
  'LY-010': ['AAI005', 'AAI001'],
  'LY-011': ['AAI005'],
  'LY-012': ['AAI006'],
  'LY-013': ['AAI006', 'AAI002'],
  'LY-014': ['AAI002', 'AAI009'],
  'LY-015': ['AAI002', 'AAI009'],
  'LY-016': ['AAI007', 'AAI009'],
  'LY-017': ['AAI007', 'AAI006'],
  'LY-018': ['AAI005'],
  // Hermes (HM)
  'HM-001': ['AAI001'],
  'HM-002': ['AAI001'],
  'HM-003': ['AAI001'],
  'HM-004': ['AAI001', 'AAI005'],
  'HM-005': ['AAI005', 'AAI001'],
  'HM-006': ['AAI009'],
  'HM-007': ['AAI009'],
  'HM-008': ['AAI012', 'AAI001'],
  'HM-009': ['AAI012', 'AAI002'],
  'HM-010': ['AAI009', 'AAI002'],
  // Coding agents (CC/CD/CG/CDX/OPC/GEM/QC/CUR/GHC)
  'CC-001': ['AAI012', 'AAI001'],
  'CC-002': ['AAI001', 'AAI002'],
  'CC-003': ['AAI002', 'AAI001'],
  'CC-004': ['AAI001'],
  'CC-005': ['AAI009'],
  'CC-006': ['AAI007', 'AAI009'],
  'CC-007': ['AAI001', 'AAI002'],
  'CC-008': ['AAI001'],
  'CC-009': ['AAI005', 'AAI002'],
  'CC-010': ['AAI002', 'AAI003'],
  'CC-011': ['AAI003', 'AAI007'],
  'CC-012': ['AAI006', 'AAI003'],
  'CD-001': ['AAI001'],
  'CD-002': ['AAI001'],
  'CD-003': ['AAI009'],
  'CD-004': ['AAI009'],
  'CD-005': ['AAI009'],
  'CD-006': ['AAI012', 'AAI001'],
  'CD-007': ['AAI005', 'AAI002'],
  'CD-008': ['AAI002', 'AAI001'],
  'CD-009': ['AAI002', 'AAI001'],
  'CD-010': ['AAI001'],
  'CDX-001': ['AAI012', 'AAI001'],
  'CDX-002': ['AAI002', 'AAI005'],
  'CDX-003': ['AAI001'],
  'CDX-004': ['AAI009'],
  'CDX-005': ['AAI005', 'AAI001'],
  'CDX-006': ['AAI001', 'AAI012'],
  'CDX-007': ['AAI006', 'AAI003'],
  'CDX-008': ['AAI001', 'AAI012'],
  'CDX-009': ['AAI002', 'AAI001'],
  'CG-003': ['AAI011'],
  'CG-004': ['AAI005'],
  'CG-005': ['AAI009'],
  'CG-006': ['AAI007', 'AAI009'],
  'CUR-001': ['AAI002', 'AAI005'],
  'CUR-002': ['AAI012', 'AAI001'],
  'CUR-003': ['AAI001', 'AAI002'],
  'CUR-004': ['AAI001'],
  'CUR-005': ['AAI001'],
  'CUR-006': ['AAI009'],
  'CUR-007': ['AAI011'],
  'CUR-008': ['AAI005', 'AAI002'],
  'CUR-009': ['AAI001', 'AAI002'],
  'CUR-010': ['AAI011'],
  'GEM-001': ['AAI001'],
  'GEM-002': ['AAI001'],
  'GEM-003': ['AAI001', 'AAI002'],
  'GEM-004': ['AAI012', 'AAI001'],
  'GEM-005': ['AAI002', 'AAI005'],
  'GEM-006': ['AAI005', 'AAI002'],
  'GEM-007': ['AAI009'],
  'GEM-008': ['AAI009'],
  'GEM-009': ['AAI012', 'AAI001'],
  'GEM-010': ['AAI006', 'AAI003'],
  'GHC-001': ['AAI006'],
  'GHC-002': ['AAI012', 'AAI001'],
  'GHC-003': ['AAI001'],
  'GHC-004': ['AAI009'],
  'GHC-005': ['AAI009'],
  'GHC-006': ['AAI009'],
  'GHC-007': ['AAI002'],
  'GHC-008': ['AAI006', 'AAI003'],
  'OPC-001': ['AAI001'],
  'OPC-002': ['AAI001', 'AAI012'],
  'OPC-003': ['AAI009'],
  'OPC-004': ['AAI011'],
  'OPC-005': ['AAI009', 'AAI002'],
  'OPC-006': ['AAI007', 'AAI001'],
  'OPC-007': ['AAI006', 'AAI003'],
  'OPC-008': ['AAI012', 'AAI001'],
  'OPC-009': ['AAI009'],
  'OPC-010': ['AAI009'],
  'OPC-011': ['AAI005'],
  'OPC-012': ['AAI009'],
  'QC-001': ['AAI001'],
  'QC-002': ['AAI001'],
  'QC-003': ['AAI012', 'AAI001'],
  'QC-004': ['AAI007', 'AAI012'],
  'QC-005': ['AAI001'],
  'QC-006': ['AAI009'],
  'QC-007': ['AAI009'],
  'QC-008': ['AAI012', 'AAI001'],
  'QC-009': ['AAI011'],
  'QC-010': ['AAI006', 'AAI003'],
};

export function owaspAgenticForCheckId(id: string): OwaspAgenticId[] {
  return CHECK_AGENTIC_MAP[id] ?? [];
}

/** Populate `owaspAgentic` on each check module from the central map (registry
 *  metadata; reporting reads the map directly). */
export function applyAgenticTags(checks: CheckModule[]): void {
  for (const check of checks) {
    const ids = CHECK_AGENTIC_MAP[check.id];
    if (ids && ids.length > 0) check.owaspAgentic = ids;
  }
}

export interface OwaspAgenticCoverageRow {
  id: OwaspAgenticId;
  title: string;
  checks: string[]; // check IDs in this result that map to this risk
  failed: number; // how many of those failed
  covered: boolean; // any check for this risk ran in THIS result
  inCatalog: boolean; // VASO has at least one check for this risk at all
}

/** Risks with at least one check anywhere in the catalog. Lets reports tell a
 *  true scanner gap (AAI014 — no check exists) apart from a risk that simply
 *  wasn't exercised by the agents in a given scan. */
export const AGENTIC_RISKS_IN_CATALOG: ReadonlySet<OwaspAgenticId> = new Set(
  Object.values(CHECK_AGENTIC_MAP).flat(),
);

/**
 * Compute OWASP Agentic AI Top 10 coverage for a scan result: for each risk,
 * which checks ran, and how many failed. A check counts toward every risk it
 * maps to (multi-tag).
 */
export function computeOwaspAgenticCoverage(result: ScanResult): OwaspAgenticCoverageRow[] {
  const byRisk = new Map<OwaspAgenticId, { checks: Set<string>; failed: number }>();
  for (const id of Object.keys(OWASP_AGENTIC_TITLES) as OwaspAgenticId[]) {
    byRisk.set(id, { checks: new Set(), failed: 0 });
  }

  for (const agent of result.agents) {
    for (const finding of agent.results) {
      const risks = CHECK_AGENTIC_MAP[finding.id];
      if (!risks) continue;
      for (const risk of risks) {
        const bucket = byRisk.get(risk)!;
        bucket.checks.add(finding.id);
        if (!finding.passed) bucket.failed += 1;
      }
    }
  }

  return (Object.keys(OWASP_AGENTIC_TITLES) as OwaspAgenticId[]).map((id) => {
    const b = byRisk.get(id)!;
    return {
      id,
      title: OWASP_AGENTIC_TITLES[id],
      checks: [...b.checks].sort(),
      failed: b.failed,
      covered: b.checks.size > 0,
      inCatalog: AGENTIC_RISKS_IN_CATALOG.has(id),
    };
  });
}

/** True when the result contains any Agentic-mapped findings (i.e. the coverage
 *  section is worth rendering). */
export function hasOwaspAgenticFindings(result: ScanResult): boolean {
  return result.agents.some((a) => a.results.some((r) => CHECK_AGENTIC_MAP[r.id]));
}

export function renderOwaspAgenticCoverageMarkdown(result: ScanResult): string {
  if (!hasOwaspAgenticFindings(result)) return '';
  const rows = computeOwaspAgenticCoverage(result);
  const lines: string[] = [
    '## OWASP Agentic AI Top 10 Coverage',
    '',
    '| Risk | Title | Checks | Status |',
    '| --- | --- | --- | --- |',
  ];
  for (const row of rows) {
    let status: string;
    if (!row.inCatalog) {
      // No check exists for this risk anywhere — a genuine static-scanner gap.
      status = 'not covered (runtime/behavioral)';
    } else if (!row.covered) {
      // VASO has checks for this risk, but none ran against the scanned agents.
      status = 'no findings in this scan';
    } else if (row.failed > 0) {
      status = `⚠️ ${row.failed} finding(s)`;
    } else {
      status = '✅ pass';
    }
    lines.push(`| ${row.id} | ${row.title} | ${row.checks.join(', ') || '—'} | ${status} |`);
  }
  lines.push('');
  return lines.join('\n');
}
