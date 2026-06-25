import { createHash } from 'node:crypto';
import type { ScanResult, AgentScanResult, CheckResult, Severity } from '../core/types.js';
import type { Reporter } from './reporter.js';
import { VERSION } from '../version.js';
import { checkRegistry } from '../core/check-registry.js';
import { owaspAgenticForCheckId, OWASP_AGENTIC_TITLES } from './owasp-agentic.js';
import { owaspMcpForCheckId, OWASP_MCP_TITLES } from './owasp-mcp.js';

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
    const executionSuccessful = !this.hadExecutionError(result);

    const sarifLog = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'VASO',
            fullName: 'VULNEX Agent Security Observer',
            version: VERSION,
            informationUri: 'https://github.com/vulnex/vaso',
            rules: this.buildRules(),
          },
        },
        results: this.buildResults(result),
        invocations: [{
          executionSuccessful,
          startTimeUtc: result.timestamp,
          ...(executionSuccessful ? {} : {
            toolExecutionNotifications: this.buildNotifications(result),
          }),
        }],
      }],
    };

    return JSON.stringify(sarifLog, null, 2);
  }

  /** A scan is only "successful" if every check produced a real verdict. The
   *  engine flags any check it couldn't evaluate (threw, or adapter failed to
   *  detect/parse) with `errored: true`; presence of any such result means the
   *  scan was partial, and SARIF should say so rather than claim a clean run. */
  private hadExecutionError(result: ScanResult): boolean {
    return result.agents.some(a => a.results.some(r => r.errored));
  }

  private buildNotifications(result: ScanResult) {
    const notes: object[] = [];
    for (const agent of result.agents) {
      for (const check of agent.results) {
        if (!check.errored) continue;
        notes.push({
          level: 'error',
          message: { text: check.message },
          associatedRule: { id: check.id },
        });
      }
    }
    return notes;
  }

  /** Advertise the full check catalogue, not just the checks that happened to
   *  run on the scanned host(s) — so consumers can browse every rule VASO
   *  enforces and `result.ruleId` always resolves. Assumes `registerAllChecks()`
   *  has populated the registry (the CLI does this at startup). */
  private buildRules() {
    return checkRegistry.getAll().map(check => {
      const owasp = owaspMcpForCheckId(check.id);
      const properties: Record<string, unknown> = { category: check.category };
      const tags: string[] = [];
      if (owasp) {
        properties.owaspMcp = owasp;
        tags.push(`owasp-mcp/${owasp}`, `OWASP MCP Top 10: ${owasp} ${OWASP_MCP_TITLES[owasp]}`);
      }
      const agentic = owaspAgenticForCheckId(check.id);
      if (agentic.length > 0) {
        properties.owaspAgentic = agentic;
        for (const a of agentic) {
          tags.push(`owasp-agentic/${a}`, `OWASP Agentic AI Top 10: ${a} ${OWASP_AGENTIC_TITLES[a]}`);
        }
      }
      if (tags.length > 0) {
        properties.tags = tags;
      }
      return {
        id: check.id,
        name: check.name,
        shortDescription: { text: check.name },
        fullDescription: { text: check.description },
        defaultConfiguration: {
          level: SARIF_LEVEL_MAP[check.severity],
        },
        properties,
      };
    });
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
          partialFingerprints: { 'vaso/v1': this.fingerprint(agent, check) },
          ...(agent.installation.agentName ? {
            properties: { agentName: agent.installation.agentName },
          } : {}),
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

  /** Stable cross-run identity for a finding. Keyed on the *logical* identity
   *  (agent install + rule + evidence file), deliberately excluding line number
   *  and snippet so the fingerprint survives unrelated edits that shift the
   *  finding's position — the line still travels in `locations` for display.
   *  Versioned key (`vaso/v1`) so the scheme can evolve without silently
   *  invalidating every existing alert's identity in one release. */
  private fingerprint(agent: AgentScanResult, check: CheckResult): string {
    const firstFile = check.evidence?.[0]?.file ?? '';
    const identity = [
      agent.installation.agent,
      agent.installation.installDir,
      check.id,
      firstFile,
    ].join('\0');
    return createHash('sha256').update(identity).digest('hex');
  }
}
