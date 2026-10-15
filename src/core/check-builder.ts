import type {
  AgentType,
  CheckCategory,
  CheckModule,
  CheckResult,
  Evidence,
  FixResult,
  ScanContext,
  Severity,
  Platform,
} from './types.js';

export interface CheckHelpers {
  /**
   * Build a result with the module's id/name/category. Severity defaults to
   * the module-declared severity but can be overridden (for checks like
   * MCP-008 that escalate based on what they found).
   */
  result(args: {
    passed: boolean;
    message: string;
    evidence?: Evidence[];
    severity?: Severity;
    fixable?: boolean;
    fixDescription?: string;
  }): CheckResult;

  /**
   * Build from an evidence array. `passed` inferred from `evidence.length === 0`,
   * message templated from `passed`/`failed` strings. Empty evidence returns
   * `evidence: undefined` (not `[]`) to match downstream conventions.
   * When every evidence item is `mitigated`, severity drops to 'info'.
   */
  fromEvidence(
    evidence: Evidence[],
    opts: {
      passed: string;
      failed: (count: number) => string;
      severity?: Severity;
      fixable?: boolean;
      fixDescription?: string;
    },
  ): CheckResult;

  /**
   * Shortcut for early-return when a precondition is missing
   * (e.g. SKL-001 with no skills directory). Always passes.
   */
  passed(message: string): CheckResult;
}

export interface DefineCheckArgs {
  id: string;
  name: string;
  category: CheckCategory;
  severity: Severity;
  description: string;
  supportedAgents?: AgentType[];
  excludedAgents?: AgentType[];
  supportedPlatforms?: Platform[];
  run(ctx: ScanContext, h: CheckHelpers): Promise<CheckResult>;
  fix?(ctx: ScanContext): Promise<FixResult>;
}

export function defineCheck(args: DefineCheckArgs): CheckModule {
  const { run, fix, ...meta } = args;

  const helpers: CheckHelpers = {
    result(r) {
      return {
        id: meta.id,
        name: meta.name,
        category: meta.category,
        severity: r.severity ?? meta.severity,
        passed: r.passed,
        message: r.message,
        evidence: r.evidence && r.evidence.length > 0 ? r.evidence : undefined,
        // Nothing to fix on a pass
        fixable: r.passed ? undefined : r.fixable,
        fixDescription: r.fixDescription,
      };
    },
    fromEvidence(evidence, opts) {
      // Every finding mitigated (blocked by parent-directory permissions, test
      // code, an untrusted project…) → informational, and nothing for
      // `vaso fix` to do: a fix is offered only for live exposure
      const allMitigated = evidence.length > 0 && evidence.every(e => e.mitigated);
      return helpers.result({
        passed: evidence.length === 0,
        message: evidence.length === 0 ? opts.passed : opts.failed(evidence.length),
        evidence,
        severity: allMitigated ? 'info' : opts.severity,
        fixable: opts.fixable && !allMitigated,
        fixDescription: opts.fixDescription,
      });
    },
    passed(message) {
      return helpers.result({ passed: true, message });
    },
  };

  const module: CheckModule = {
    ...meta,
    // `fixable` promises `vaso fix` can act — never true for a check that
    // has no fix() (the description still says how to fix it by hand).
    run: fix
      ? (ctx) => run(ctx, helpers)
      : async (ctx) => {
          const r = await run(ctx, helpers);
          if (r.fixable) r.fixable = false;
          return r;
        },
  };

  if (fix) module.fix = fix;
  return module;
}
