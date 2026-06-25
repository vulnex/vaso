import { describe, it, expect, beforeAll } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SarifReporter } from './sarif.js';
import { checkRegistry } from '../core/check-registry.js';
import { registerAllChecks } from '../checks/index.js';
import type { ScanResult, AgentScanResult } from '../core/types.js';

// buildRules() now advertises the full catalogue from the registry, so it must
// be populated (the CLI does this at startup). Register once for the file.
beforeAll(() => {
  if (checkRegistry.count() === 0) registerAllChecks();
});

/** One agent installation with a single failing CFG-001 (with evidence). */
function failingAgent(overrides: Partial<AgentScanResult> = {}): AgentScanResult {
  return {
    agent: 'openclaw',
    installation: { agent: 'openclaw', installDir: '/tmp', configFiles: [] },
    results: [{
      id: 'CFG-001',
      name: 'Gateway Binding',
      category: 'config',
      severity: 'critical',
      passed: false,
      message: 'Gateway bound to 0.0.0.0',
      evidence: [{ file: '/tmp/config.json', line: 5, snippet: '"host": "0.0.0.0"' }],
    }],
    score: 88,
    grade: 'B',
    ...overrides,
  };
}

function scanWith(agents: AgentScanResult[]): ScanResult {
  return {
    timestamp: '2026-02-20T00:00:00.000Z',
    agents,
    totalScore: 88,
    totalGrade: 'B',
    summary: { critical: 1, warning: 0, info: 0, passed: 0, total: 1 },
  };
}

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

  it('emits a stable partialFingerprint that survives line-number changes', () => {
    const base = scanWith([failingAgent()]);
    const shifted = scanWith([failingAgent()]);
    shifted.agents[0].results[0].evidence![0].line = 42; // same file, moved down

    const fp = (r: ScanResult) =>
      JSON.parse(new SarifReporter().render(r))
        .runs[0].results[0].partialFingerprints['vaso/v1'];

    expect(fp(base)).toBeTruthy();
    expect(fp(base)).toBe(fp(shifted)); // identity stable across line move
  });

  it('gives different rules/files distinct partialFingerprints', () => {
    const a = failingAgent();
    const b = failingAgent({
      results: [{
        id: 'CFG-002',
        name: 'API Key Exposure',
        category: 'config',
        severity: 'critical',
        passed: false,
        message: 'Plaintext API key',
        evidence: [{ file: '/tmp/auth.json', line: 1 }],
      }],
    });
    const sarif = JSON.parse(new SarifReporter().render(scanWith([a, b])));
    const [fp1, fp2] = sarif.runs[0].results.map(
      (r: { partialFingerprints: Record<string, string> }) => r.partialFingerprints['vaso/v1'],
    );
    expect(fp1).not.toBe(fp2);
  });

  it('reports executionSuccessful: false (+ notifications) when a check errored', () => {
    const agent = failingAgent({
      results: [{
        id: 'SKL-001',
        name: 'Skill Data Flow',
        category: 'skills',
        severity: 'warning',
        passed: false,
        errored: true,
        message: 'Check errored and was not completed: boom',
      }],
    });
    const inv = JSON.parse(new SarifReporter().render(scanWith([agent]))).runs[0].invocations[0];

    expect(inv.executionSuccessful).toBe(false);
    expect(inv.toolExecutionNotifications).toEqual(expect.arrayContaining([
      expect.objectContaining({ level: 'error', associatedRule: { id: 'SKL-001' } }),
    ]));
  });

  it('reports executionSuccessful: true for a clean scan (no notifications key)', () => {
    const inv = JSON.parse(new SarifReporter().render(scanWith([failingAgent()]))).runs[0].invocations[0];
    expect(inv.executionSuccessful).toBe(true);
    expect(inv.toolExecutionNotifications).toBeUndefined();
  });

  it('lists the full check catalogue in tool.driver.rules, not just checks that ran', () => {
    // A scan that ran only CFG-001 must still advertise every registered rule,
    // so consumers can browse the full rule set and ruleId always resolves.
    const sarif = JSON.parse(new SarifReporter().render(scanWith([failingAgent()])));
    const rules = sarif.runs[0].tool.driver.rules;
    expect(rules.length).toBe(checkRegistry.count());
    const ids = rules.map((r: { id: string }) => r.id);
    expect(ids).toContain('MCP-031'); // a rule that did NOT run this scan
    // every emitted result's ruleId resolves to a declared rule
    for (const res of sarif.runs[0].results) {
      expect(ids).toContain(res.ruleId);
    }
  });
});
