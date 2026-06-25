import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SarifReporter } from './sarif.js';
import type { ScanResult } from '../core/types.js';

describe('SarifReporter', () => {
  it('generates valid SARIF structure', () => {
    const result: ScanResult = {
      timestamp: '2026-02-20T00:00:00.000Z',
      agents: [{
        agent: 'openclaw',
        installation: { agent: 'openclaw', installDir: '/tmp', configFiles: [] },
        results: [
          {
            id: 'CFG-001',
            name: 'Gateway Binding',
            category: 'config',
            severity: 'critical',
            passed: false,
            message: 'Gateway bound to 0.0.0.0',
            evidence: [{ file: '/tmp/config.json', line: 5, snippet: '"host": "0.0.0.0"' }],
          },
          {
            id: 'CFG-002',
            name: 'API Key Exposure',
            category: 'config',
            severity: 'critical',
            passed: true,
            message: 'No API keys found',
          },
        ],
        score: 88,
        grade: 'B',
      }],
      totalScore: 88,
      totalGrade: 'B',
      summary: { critical: 1, warning: 0, info: 0, passed: 1, total: 2 },
    };

    const reporter = new SarifReporter();
    const output = reporter.render(result);
    const sarif = JSON.parse(output);

    console.log(`[SARIF] version: ${sarif.version}, runs: ${sarif.runs.length}`);
    console.log(`[SARIF] tool: ${sarif.runs[0].tool.driver.name}, results: ${sarif.runs[0].results.length}`);
    console.log(`[SARIF] first result → ruleId: ${sarif.runs[0].results[0].ruleId}, level: ${sarif.runs[0].results[0].level}`);

    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.name).toBe('VASO');
    expect(sarif.runs[0].results).toHaveLength(1); // Only failed checks
    expect(sarif.runs[0].results[0].ruleId).toBe('CFG-001');
    expect(sarif.runs[0].results[0].level).toBe('error');
  });

  it('reports the running package.json version in tool.driver.version', () => {
    // Drift guard: tool.driver.version was once hardcoded to '0.2.1' and
    // silently misreported VASO's version in every SARIF report (GitHub Code
    // Scanning UI, result fingerprinting, provenance). Assert it tracks the
    // manifest so the two can never diverge again.
    const pkgPath = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { version: string };

    const result: ScanResult = {
      timestamp: '2026-02-20T00:00:00.000Z',
      agents: [],
      totalScore: 100,
      totalGrade: 'A',
      summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
    };

    const sarif = JSON.parse(new SarifReporter().render(result));

    expect(sarif.runs[0].tool.driver.version).toBe(pkg.version);
  });
});
