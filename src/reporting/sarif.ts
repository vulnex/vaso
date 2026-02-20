import type { ScanResult, CheckResult, Severity } from '../core/types.js';
import type { Reporter } from './reporter.js';

const SARIF_SEVERITY_MAP: Record<Severity, string> = {
  critical: 'error',
  warning: 'warning',
  info: 'note',
};

const SARIF_LEVEL_MAP: Record<Severity, string> = {
  critical: 'error',
  warning: 'warning',
  info: 'note',
};

export class SarifReporter implements Reporter {
  readonly format = 'sarif';

  render(result: ScanResult): string {
    const sarifLog = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'VASO',
            fullName: 'VULNEX Agent Security Observer',
            version: '0.1.0',
            informationUri: 'https://github.com/vulnex/vaso',
            rules: this.buildRules(result),
          },
        },
        results: this.buildResults(result),
        invocations: [{
          executionSuccessful: true,
          startTimeUtc: result.timestamp,
        }],
      }],
    };

    return JSON.stringify(sarifLog, null, 2);
  }

  private buildRules(result: ScanResult) {
    const ruleMap = new Map<string, CheckResult>();

    for (const agent of result.agents) {
      for (const check of agent.results) {
        if (!ruleMap.has(check.id)) {
          ruleMap.set(check.id, check);
        }
      }
    }

    return Array.from(ruleMap.values()).map(check => ({
      id: check.id,
      name: check.name,
      shortDescription: { text: check.name },
      defaultConfiguration: {
        level: SARIF_LEVEL_MAP[check.severity],
      },
      properties: {
        category: check.category,
      },
    }));
  }

  private buildResults(result: ScanResult) {
    const results: object[] = [];

    for (const agent of result.agents) {
      for (const check of agent.results) {
        if (check.passed) continue;

        const sarifResult: Record<string, unknown> = {
          ruleId: check.id,
          level: SARIF_SEVERITY_MAP[check.severity],
          message: { text: check.message },
          locations: [],
        };

        if (check.evidence) {
          (sarifResult.locations as object[]) = check.evidence.map(e => ({
            physicalLocation: {
              artifactLocation: { uri: e.file },
              ...(e.line ? {
                region: {
                  startLine: e.line,
                  snippet: e.snippet ? { text: e.snippet } : undefined,
                },
              } : {}),
            },
          }));
        }

        results.push(sarifResult);
      }
    }

    return results;
  }
}
