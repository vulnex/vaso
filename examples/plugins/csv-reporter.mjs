/**
 * VASO Example Plugin: CSV Reporter
 *
 * Demonstrates: api.registerReporter() — adding a custom output format.
 *
 * Registers a "csv" format usable via `vaso scan --format csv`.
 * Produces RFC 4180-compliant CSV output:
 *   - One row per evidence item (denormalized), or one row per check if no evidence
 *   - Summary row at the bottom with totals and score/grade
 *   - Proper quoting for fields containing commas, quotes, or newlines
 *
 * Install: cp csv-reporter.mjs ~/.vaso/plugins/
 * Verify:  vaso ext list
 * Usage:   vaso scan --format csv > report.csv
 */

const HEADERS = [
  'Timestamp',
  'Agent',
  'Check ID',
  'Name',
  'Category',
  'Severity',
  'Passed',
  'Message',
  'Evidence File',
  'Evidence Line',
  'Evidence Detail',
];

/**
 * Escape a CSV field per RFC 4180.
 * Fields containing commas, double-quotes, or newlines are wrapped in double-quotes,
 * with any internal double-quotes doubled.
 */
function escapeField(value) {
  const str = value === null || value === undefined ? '' : String(value);
  if (str.includes('"') || str.includes(',') || str.includes('\n') || str.includes('\r')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/**
 * Build a CSV line from an array of field values.
 */
function csvLine(fields) {
  return fields.map(escapeField).join(',');
}

export default {
  meta: {
    name: 'csv-reporter',
    version: '1.0.0',
    description: 'CSV output format for VASO scan results (RFC 4180)',
  },

  register(api) {
    // registerReporter takes a format name and a factory function that returns
    // a Reporter object with { format: string, render(result: ScanResult): string }.
    api.registerReporter('csv', () => ({
      format: 'csv',

      render(result) {
        const rows = [];

        // Header row
        rows.push(csvLine(HEADERS));

        // Data rows — one per evidence item, or one per check if no evidence
        for (const agentResult of result.agents) {
          const agentName = agentResult.installation.agentName || agentResult.agent;

          for (const check of agentResult.results) {
            if (check.evidence && check.evidence.length > 0) {
              // One row per evidence item (denormalized)
              for (const ev of check.evidence) {
                rows.push(csvLine([
                  result.timestamp,
                  agentName,
                  check.id,
                  check.name,
                  check.category,
                  check.severity,
                  check.passed ? 'PASS' : 'FAIL',
                  check.message,
                  ev.file || '',
                  ev.line != null ? ev.line : '',
                  ev.detail || ev.snippet || '',
                ]));
              }
            } else {
              // No evidence — single row for this check
              rows.push(csvLine([
                result.timestamp,
                agentName,
                check.id,
                check.name,
                check.category,
                check.severity,
                check.passed ? 'PASS' : 'FAIL',
                check.message,
                '',
                '',
                '',
              ]));
            }
          }
        }

        // Summary row
        const { summary, totalScore, totalGrade } = result;
        const agents = result.agents.map(a => a.agent).join('; ');
        rows.push(csvLine([
          result.timestamp,
          agents,
          'SUMMARY',
          `Score: ${totalScore}/100 (${totalGrade})`,
          '',
          '',
          '',
          `${summary.passed}/${summary.total} passed | ${summary.critical} critical, ${summary.warning} warning, ${summary.info} info`,
          '',
          '',
          '',
        ]));

        return rows.join('\n') + '\n';
      },
    }));
  },
};
