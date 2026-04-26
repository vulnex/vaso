import type { ScanResult } from '../core/types.js';
import type { Reporter } from './reporter.js';

const COLUMNS = [
  'timestamp',
  'agent',
  'agent_name',
  'check_id',
  'check_name',
  'category',
  'severity',
  'passed',
  'message',
  'file',
  'line',
  'snippet',
  'detail',
] as const;

function csvEscape(value: string): string {
  if (value === '') return '';
  if (/[",\r\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function row(values: readonly (string | number | boolean | undefined)[]): string {
  return values
    .map(v => v === undefined || v === null ? '' : csvEscape(String(v)))
    .join(',');
}

export class CsvReporter implements Reporter {
  readonly format = 'csv';

  render(result: ScanResult): string {
    const lines: string[] = [];
    lines.push(row(COLUMNS));

    for (const agent of result.agents) {
      const agentName = agent.installation.agentName ?? '';
      for (const r of agent.results) {
        // One row per evidence entry; if no evidence, one row with empty location fields.
        const evidences = r.evidence && r.evidence.length > 0
          ? r.evidence
          : [undefined];

        for (const e of evidences) {
          lines.push(row([
            result.timestamp,
            agent.agent,
            agentName,
            r.id,
            r.name,
            r.category,
            r.severity,
            r.passed,
            r.message,
            e?.file ?? '',
            e?.line ?? '',
            e?.snippet ?? '',
            e?.detail ?? '',
          ]));
        }
      }
    }

    return lines.join('\n') + '\n';
  }
}
