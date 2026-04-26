import { describe, it, expect } from 'vitest';
import { CsvReporter } from './csv.js';
import type { ScanResult } from '../core/types.js';

function makeScanResult(overrides?: Partial<ScanResult>): ScanResult {
  return {
    timestamp: '2026-02-21T12:00:00.000Z',
    agents: [{
      agent: 'openclaw',
      installation: { agent: 'openclaw', installDir: '/x', configFiles: [] },
      results: [
        {
          id: 'CFG-001', name: 'Gateway Binding', category: 'config', severity: 'critical',
          passed: false, message: 'Gateway bound to 0.0.0.0',
          evidence: [{ file: '/x/config.yaml', line: 12, snippet: 'host: 0.0.0.0', detail: 'public bind' }],
        },
        {
          id: 'CFG-002', name: 'API Key Exposure', category: 'config', severity: 'critical',
          passed: true, message: 'No API keys found',
        },
      ],
      score: 65, grade: 'C',
    }],
    totalScore: 65, totalGrade: 'C',
    summary: { critical: 1, warning: 0, info: 0, passed: 1, total: 2 },
    ...overrides,
  };
}

function rows(csv: string): string[][] {
  // Naive split for tests — fine because our test fixtures avoid embedded newlines
  return csv.trim().split('\n').map(line => {
    const out: string[] = [];
    let cur = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i];
      if (c === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (c === '"') { inQuotes = !inQuotes; }
      else if (c === ',' && !inQuotes) { out.push(cur); cur = ''; }
      else { cur += c; }
    }
    out.push(cur);
    return out;
  });
}

describe('CsvReporter', () => {
  it('has format set to csv', () => {
    expect(new CsvReporter().format).toBe('csv');
  });

  it('emits a header row with the expected columns', () => {
    const out = new CsvReporter().render(makeScanResult());
    const r = rows(out);
    expect(r[0]).toEqual([
      'timestamp', 'agent', 'agent_name', 'check_id', 'check_name', 'category',
      'severity', 'passed', 'message', 'file', 'line', 'snippet', 'detail',
    ]);
  });

  it('emits one row per evidence entry on a failing check', () => {
    const result = makeScanResult({
      agents: [{
        agent: 'openclaw',
        installation: { agent: 'openclaw', installDir: '/x', configFiles: [] },
        results: [{
          id: 'IOC-001', name: 'C2 IPs', category: 'ioc', severity: 'critical',
          passed: false, message: '2 hits',
          evidence: [
            { file: '/x/a.js', line: 10, detail: '1.2.3.4' },
            { file: '/x/b.js', line: 20, detail: '5.6.7.8' },
          ],
        }],
        score: 0, grade: 'F',
      }],
    });
    const r = rows(new CsvReporter().render(result));
    expect(r).toHaveLength(3); // header + 2 evidence rows
    expect(r[1][9]).toBe('/x/a.js');
    expect(r[1][12]).toBe('1.2.3.4');
    expect(r[2][9]).toBe('/x/b.js');
    expect(r[2][12]).toBe('5.6.7.8');
  });

  it('emits one row with empty location fields when there is no evidence', () => {
    const r = rows(new CsvReporter().render(makeScanResult()));
    // CFG-001 row + CFG-002 (no evidence) row
    expect(r).toHaveLength(3);
    const cfg002 = r[2];
    expect(cfg002[3]).toBe('CFG-002');
    expect(cfg002[7]).toBe('true'); // passed
    expect(cfg002[9]).toBe('');     // file
    expect(cfg002[10]).toBe('');    // line
  });

  it('escapes commas, quotes, and newlines correctly', () => {
    const result = makeScanResult({
      agents: [{
        agent: 'openclaw',
        installation: { agent: 'openclaw', installDir: '/x', configFiles: [] },
        results: [{
          id: 'X', name: 'X', category: 'config', severity: 'warning',
          passed: false, message: 'has, comma and "quotes" and\nnewline',
          evidence: [{ file: '/path with, comma' }],
        }],
        score: 100, grade: 'A',
      }],
    });
    const out = new CsvReporter().render(result);
    expect(out).toContain('"has, comma and ""quotes"" and\nnewline"');
    expect(out).toContain('"/path with, comma"');
  });

  it('handles an empty agents array (header only)', () => {
    const out = new CsvReporter().render(makeScanResult({
      agents: [],
      totalScore: 100, totalGrade: 'A',
      summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
    }));
    const r = rows(out);
    expect(r).toHaveLength(1);
    expect(r[0][0]).toBe('timestamp');
  });

  it('includes the agent_name column when set', () => {
    const result = makeScanResult();
    result.agents[0].installation.agentName = 'subagent-a';
    const r = rows(new CsvReporter().render(result));
    expect(r[1][2]).toBe('subagent-a');
  });
});
