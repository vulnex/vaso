import type { ScanResult, AgentScanResult, Evidence, Grade, Severity } from '../core/types.js';
import {
  computeOwaspAgenticCoverage,
  hasOwaspAgenticFindings,
  type OwaspAgenticCoverageRow,
} from './owasp-agentic.js';
import {
  computeOwaspMcpCoverage,
  hasOwaspMcpFindings,
  type OwaspMcpCoverageRow,
} from './owasp-mcp.js';
import type { Reporter } from './reporter.js';

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function gradeColor(grade: Grade): string {
  switch (grade) {
    case 'A':
    case 'B':
      return '#16a34a';
    case 'C':
      return '#d97706';
    case 'D':
    case 'F':
      return '#dc2626';
  }
}

function severityColor(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return '#dc2626';
    case 'warning':
      return '#d97706';
    case 'info':
      return '#2563eb';
  }
}

const CSS = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #f8fafc;
    color: #1e293b;
    line-height: 1.6;
    padding: 2rem;
    max-width: 1200px;
    margin: 0 auto;
  }
  .header {
    text-align: center;
    margin-bottom: 2rem;
    padding: 2rem;
    background: #fff;
    border-radius: 12px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  }
  .header h1 {
    font-size: 1.8rem;
    color: #0f172a;
    margin-bottom: 0.5rem;
  }
  .header .timestamp {
    color: #64748b;
    font-size: 0.9rem;
  }
  .score {
    display: inline-block;
    font-size: 3rem;
    font-weight: 700;
    margin: 1rem 0 0.25rem;
  }
  .grade {
    font-size: 1.5rem;
    font-weight: 600;
  }
  .summary-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }
  .card {
    background: #fff;
    border-radius: 8px;
    padding: 1.25rem;
    text-align: center;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  }
  .card .count {
    font-size: 2rem;
    font-weight: 700;
  }
  .card .label {
    font-size: 0.85rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .agent-section {
    background: #fff;
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  }
  .agent-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 1rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid #e2e8f0;
  }
  .agent-header h2 {
    font-size: 1.3rem;
    color: #0f172a;
  }
  .agent-meta {
    color: #64748b;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }
  .agent-meta span {
    margin-right: 1.5rem;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 1rem;
    font-size: 0.9rem;
  }
  th {
    background: #f1f5f9;
    text-align: left;
    padding: 0.6rem 0.75rem;
    font-weight: 600;
    color: #475569;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  td {
    padding: 0.6rem 0.75rem;
    border-bottom: 1px solid #f1f5f9;
  }
  tr:nth-child(even) td {
    background: #fafbfc;
  }
  .severity-badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    color: #fff;
    text-transform: uppercase;
  }
  .evidence {
    font-size: 0.8rem;
    color: #64748b;
    font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  }
  .passed-list {
    margin-top: 1rem;
  }
  .passed-list h3 {
    font-size: 0.95rem;
    color: #16a34a;
    margin-bottom: 0.5rem;
  }
  .passed-list ul {
    list-style: none;
    padding: 0;
    columns: 2;
  }
  .passed-list li {
    padding: 0.2rem 0;
    font-size: 0.85rem;
    color: #64748b;
  }
  .passed-list li::before {
    content: "\\2713 ";
    color: #16a34a;
  }
  .owasp-section {
    background: #fff;
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  }
  .owasp-section h2 {
    font-size: 1.3rem;
    color: #0f172a;
    margin-bottom: 0.25rem;
  }
  .owasp-section .subtitle {
    color: #64748b;
    font-size: 0.85rem;
    margin-bottom: 1rem;
  }
  .owasp-section td.risk-id {
    font-weight: 700;
    color: #0f172a;
    white-space: nowrap;
  }
  .owasp-section td.checks {
    font-size: 0.78rem;
    color: #475569;
    font-family: "SF Mono", Monaco, "Cascadia Code", monospace;
  }
  .cov-badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 600;
    white-space: nowrap;
  }
  .cov-fail { background: #fef2f2; color: #dc2626; }
  .cov-pass { background: #f0fdf4; color: #16a34a; }
  .cov-none { background: #f1f5f9; color: #64748b; }
  .cov-gap  { background: #f8fafc; color: #94a3b8; border: 1px dashed #cbd5e1; }
  .footer {
    text-align: center;
    padding: 1.5rem;
    color: #94a3b8;
    font-size: 0.8rem;
  }
  @media (max-width: 600px) {
    body { padding: 1rem; }
    .summary-cards { grid-template-columns: repeat(2, 1fr); }
    .passed-list ul { columns: 1; }
    .agent-header { flex-direction: column; align-items: flex-start; }
  }
`;

export class HtmlReporter implements Reporter {
  readonly format = 'html';

  render(result: ScanResult): string {
    const lines: string[] = [];

    lines.push('<!DOCTYPE html>');
    lines.push('<html lang="en">');
    lines.push('<head>');
    lines.push('<meta charset="UTF-8">');
    lines.push('<meta name="viewport" content="width=device-width, initial-scale=1.0">');
    lines.push(`<title>VASO Security Scan Report — ${escapeHtml(result.timestamp)}</title>`);
    lines.push(`<style>${CSS}</style>`);
    lines.push('</head>');
    lines.push('<body>');

    // Header
    lines.push('<div class="header">');
    lines.push('<h1>VASO Security Scan Report</h1>');
    lines.push(`<div class="timestamp">${escapeHtml(result.timestamp)}</div>`);
    lines.push(`<div class="score" style="color:${gradeColor(result.totalGrade)}">${result.totalScore}/100</div>`);
    lines.push(`<div class="grade" style="color:${gradeColor(result.totalGrade)}">Grade: ${escapeHtml(result.totalGrade)}</div>`);
    if (result.agents.length > 1) {
      // Headline score is worst-case (weakest agent); show the mean as context.
      lines.push(`<div class="fleet-average">Fleet average: ${result.fleetAverage}/100</div>`);
    }
    lines.push('</div>');

    // Summary cards
    lines.push('<div class="summary-cards">');
    lines.push(this.renderCard(result.summary.critical, 'Critical', '#dc2626'));
    lines.push(this.renderCard(result.summary.warning, 'Warning', '#d97706'));
    lines.push(this.renderCard(result.summary.info, 'Info', '#2563eb'));
    lines.push(this.renderCard(result.summary.passed, 'Passed', '#16a34a'));
    lines.push('</div>');

    // Agent sections
    for (const agent of result.agents) {
      lines.push(this.renderAgent(agent));
    }

    // OWASP coverage sections
    if (hasOwaspMcpFindings(result)) {
      lines.push(this.renderOwaspMcpCoverage(result));
    }
    if (hasOwaspAgenticFindings(result)) {
      lines.push(this.renderOwaspAgenticCoverage(result));
    }

    // Footer
    lines.push('<div class="footer">Generated by VASO (VULNEX Agent Security Observer)</div>');

    lines.push('</body>');
    lines.push('</html>');

    return lines.join('\n');
  }

  private renderCard(count: number, label: string, color: string): string {
    return `<div class="card"><div class="count" style="color:${color}">${count}</div><div class="label">${label}</div></div>`;
  }

  private renderAgent(agent: AgentScanResult): string {
    const lines: string[] = [];
    const inst = agent.installation;
    const agentLabel = inst.agentName
      ? `${escapeHtml(agent.agent)} — ${escapeHtml(inst.agentName)}`
      : escapeHtml(agent.agent);

    lines.push('<div class="agent-section">');

    // Header
    lines.push('<div class="agent-header">');
    lines.push(`<h2>${agentLabel}</h2>`);
    lines.push(`<span class="grade" style="color:${gradeColor(agent.grade)}">Score: ${agent.score}/100 (${escapeHtml(agent.grade)})</span>`);
    lines.push('</div>');

    // Meta
    const metaParts: string[] = [];
    if (inst.user) metaParts.push(`<span>User: ${escapeHtml(inst.user)}</span>`);
    if (inst.profile) metaParts.push(`<span>Profile: ${escapeHtml(inst.profile)}</span>`);
    metaParts.push(`<span>Install: ${escapeHtml(inst.installDir)}</span>`);
    lines.push(`<div class="agent-meta">${metaParts.join('')}</div>`);

    // Findings table
    const failed = agent.results.filter(r => !r.passed);
    const passed = agent.results.filter(r => r.passed);

    if (failed.length > 0) {
      lines.push('<table>');
      lines.push('<thead><tr><th>ID</th><th>Name</th><th>Severity</th><th>Message</th><th>Evidence</th><th>Fixable</th></tr></thead>');
      lines.push('<tbody>');
      for (const r of failed) {
        lines.push('<tr>');
        lines.push(`<td>${escapeHtml(r.id)}</td>`);
        lines.push(`<td>${escapeHtml(r.name)}</td>`);
        lines.push(`<td><span class="severity-badge" style="background:${severityColor(r.severity)}">${escapeHtml(r.severity)}</span></td>`);
        lines.push(`<td>${escapeHtml(r.message)}</td>`);
        lines.push(`<td>${this.renderEvidence(r.evidence)}</td>`);
        lines.push(`<td>${r.fixable ? escapeHtml(r.fixDescription ?? 'Yes') : '—'}</td>`);
        lines.push('</tr>');
      }
      lines.push('</tbody>');
      lines.push('</table>');
    }

    // Passed checks
    if (passed.length > 0) {
      lines.push('<div class="passed-list">');
      lines.push(`<h3>Passed (${passed.length})</h3>`);
      lines.push('<ul>');
      for (const r of passed) {
        lines.push(`<li>${escapeHtml(r.id)}: ${escapeHtml(r.name)}</li>`);
      }
      lines.push('</ul>');
      lines.push('</div>');
    }

    lines.push('</div>');
    return lines.join('\n');
  }

  private renderOwaspAgenticCoverage(result: ScanResult): string {
    const rows = computeOwaspAgenticCoverage(result);
    const lines: string[] = ['<div class="owasp-section">'];
    lines.push('<h2>OWASP Agentic AI Top 10 Coverage</h2>');
    lines.push(
      '<div class="subtitle">How VASO\'s checks map to the OWASP Agentic AI Top 10 (precize list). ' +
        'Risks with no static signal appear as gaps.</div>',
    );
    lines.push('<table>');
    lines.push('<thead><tr><th>Risk</th><th>Title</th><th>Checks</th><th>Status</th></tr></thead>');
    lines.push('<tbody>');
    for (const row of rows) {
      lines.push('<tr>');
      lines.push(`<td class="risk-id">${escapeHtml(row.id)}</td>`);
      lines.push(`<td>${escapeHtml(row.title)}</td>`);
      lines.push(`<td class="checks">${row.checks.length > 0 ? escapeHtml(row.checks.join(', ')) : '—'}</td>`);
      lines.push(`<td>${this.agenticStatusBadge(row)}</td>`);
      lines.push('</tr>');
    }
    lines.push('</tbody></table>');
    lines.push('</div>');
    return lines.join('\n');
  }

  private agenticStatusBadge(row: OwaspAgenticCoverageRow): string {
    if (!row.inCatalog) {
      return '<span class="cov-badge cov-gap">not covered (runtime/behavioral)</span>';
    }
    if (!row.covered) {
      return '<span class="cov-badge cov-none">no findings in this scan</span>';
    }
    if (row.failed > 0) {
      return `<span class="cov-badge cov-fail">⚠️ ${row.failed} finding(s)</span>`;
    }
    return '<span class="cov-badge cov-pass">✅ pass</span>';
  }

  private renderOwaspMcpCoverage(result: ScanResult): string {
    const rows = computeOwaspMcpCoverage(result);
    const lines: string[] = ['<div class="owasp-section">'];
    lines.push('<h2>OWASP MCP Top 10 Coverage</h2>');
    lines.push(
      '<div class="subtitle">How VASO\'s MCP checks map to the OWASP MCP Top 10 (2025).</div>',
    );
    lines.push('<table>');
    lines.push('<thead><tr><th>Risk</th><th>Title</th><th>Checks</th><th>Status</th></tr></thead>');
    lines.push('<tbody>');
    for (const row of rows) {
      lines.push('<tr>');
      lines.push(`<td class="risk-id">${escapeHtml(row.id)}</td>`);
      lines.push(`<td>${escapeHtml(row.title)}</td>`);
      lines.push(`<td class="checks">${row.checks.length > 0 ? escapeHtml(row.checks.join(', ')) : '—'}</td>`);
      lines.push(`<td>${this.mcpStatusBadge(row)}</td>`);
      lines.push('</tr>');
    }
    lines.push('</tbody></table>');
    lines.push('</div>');
    return lines.join('\n');
  }

  private mcpStatusBadge(row: OwaspMcpCoverageRow): string {
    if (!row.covered) {
      return '<span class="cov-badge cov-gap">not covered (runtime/operational)</span>';
    }
    if (row.failed > 0) {
      return `<span class="cov-badge cov-fail">⚠️ ${row.failed} finding(s)</span>`;
    }
    return '<span class="cov-badge cov-pass">✅ pass</span>';
  }

  private renderEvidence(evidence?: Evidence[]): string {
    if (!evidence || evidence.length === 0) return '—';
    return evidence.map(e => {
      let text = escapeHtml(e.file);
      if (e.line) text += `:${e.line}`;
      return `<span class="evidence">${text}</span>`;
    }).join('<br>');
  }
}
