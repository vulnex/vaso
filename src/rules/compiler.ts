import { join, resolve } from 'node:path';
import type { CheckModule, CheckResult, ScanContext, Evidence, FixResult, ParsedConfig } from '../core/types.js';
import type { FSProvider } from '../core/fs-provider.js';
import { getNestedValue } from '../core/utils.js';
import { pathExists } from '../core/utils.js';
import { evaluateOperator } from './operators.js';
import { updateConfigValue } from '../remediation/config-writer.js';
import { maskConfigValue, maskCredentialsInLine } from '../reporting/serialize.js';
import { ruleInput, MAX_RULE_SCAN_MS, MAX_RULES_SCAN_MS } from './regex-safety.js';
import { truncateSnippet } from '../core/patterns.js';
import type { DeclarativeRule, RawConfigRule } from './schema.js';

/**
 * Time the rules of one scan have spent matching, per host (its FSProvider):
 * past MAX_RULES_SCAN_MS every rule stops, its result errored (the scan is
 * incomplete, exit 3). Shared by the rules `loadAndRegisterRules` compiles.
 */
export class RuleTimeBudget {
  private spent = new WeakMap<FSProvider, number>();

  used(host: FSProvider): number {
    return this.spent.get(host) ?? 0;
  }

  add(host: FSProvider, ms: number): void {
    this.spent.set(host, this.used(host) + ms);
  }

  exhausted(host: FSProvider): boolean {
    return this.used(host) > MAX_RULES_SCAN_MS;
  }
}

/** The note on a result a time budget cut short. */
function unfinishedNote(unfinished: number, what: string, total: boolean): string {
  return total
    ? ` — stopped: all rules together spent ${MAX_RULES_SCAN_MS / 1000} s matching on this host; ${unfinished} ${what} not checked`
    : ` — stopped after ${MAX_RULE_SCAN_MS / 1000} s of matching: ${unfinished} ${what} not fully scanned (the pattern is too slow on this input)`;
}

function interpolateMessage(template: string, vars: Record<string, string>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key) => vars[key] ?? '');
}

/** Whether a config rule fails on one config file. */
function configFails(config: RawConfigRule, cfg: ParsedConfig): { failed: boolean; actual: unknown } {
  const actual = getNestedValue(cfg.data, config.path);
  const conditionMatches = evaluateOperator(actual, config.operator, config.value);
  // Default: condition match = fail (detecting the bad thing)
  // pass_when: "match" = condition match means pass
  const passWhen = config.pass_when ?? 'no-match';
  return { failed: passWhen === 'match' ? !conditionMatches : conditionMatches, actual };
}

function compileConfigRule(rule: DeclarativeRule, budget: RuleTimeBudget): CheckModule['run'] {
  const { config } = rule;
  if (!config) throw new Error('No config block');

  return async (ctx: ScanContext): Promise<CheckResult> => {
    const evidence: Evidence[] = [];

    // a `matches` value is one capped regex run per config: only the scan-wide budget applies
    let unfinished = 0;
    for (const [index, cfg] of ctx.configs.entries()) {
      if (budget.exhausted(ctx.fs)) {
        unfinished = ctx.configs.length - index;
        break;
      }
      const started = performance.now();
      const { failed, actual } = configFails(config, cfg);
      budget.add(ctx.fs, performance.now() - started);
      if (failed) {
        evidence.push({
          file: cfg.filePath,
          // The value is quoted from the user's config: a credential is masked
          detail: `${config.path} = ${JSON.stringify(maskConfigValue(config.path, actual))}`,
        });
      }
    }

    return {
      id: rule.id,
      name: rule.name,
      category: rule.category,
      severity: rule.severity,
      passed: evidence.length === 0 && unfinished === 0,
      message: (evidence.length === 0
        ? `${rule.name}: passed`
        : `${rule.name}: ${evidence.length} config(s) failed — ${rule.description}`)
        + (unfinished > 0 ? unfinishedNote(unfinished, 'config(s)', true) : ''),
      evidence: evidence.length > 0 ? evidence : undefined,
      ...(unfinished > 0 ? { errored: true } : {}),
      fixable: rule.fix?.set !== undefined,
      fixDescription: rule.fix?.guidance ?? (rule.fix?.set ? `Set ${rule.fix.set} to ${JSON.stringify(rule.fix.value)}` : undefined),
    };
  };
}

function compilePatternRule(rule: DeclarativeRule, budget: RuleTimeBudget): CheckModule['run'] {
  const { pattern } = rule;
  if (!pattern) throw new Error('No pattern block');
  const re = new RegExp(pattern.regex);
  const target = pattern.target ?? 'configs';
  const msgTemplate = pattern.message ?? `Pattern match in {{file}}:{{line}} — {{snippet}}`;

  return async (ctx: ScanContext): Promise<CheckResult> => {
    const evidence: Evidence[] = [];

    // Collect files to scan: configs use raw content (already loaded), skills read from disk
    const entries: Array<{ filePath: string; content: string | null }> = [];

    if (target === 'configs' || target === 'all') {
      for (const cfg of ctx.configs) {
        entries.push({ filePath: cfg.filePath, content: cfg.raw });
      }
    }
    if (target === 'skills' || target === 'all') {
      if (ctx.skillFiles) {
        for (const f of ctx.skillFiles) {
          entries.push({ filePath: f, content: null });
        }
      }
    }

    // Time spent matching: past MAX_RULE_SCAN_MS (this rule) or
    // MAX_RULES_SCAN_MS (all rules on this host) the rule stops, and the
    // files it didn't finish are reported (the result is errored, not clean)
    let spent = 0;
    let unfinished = 0;
    const overBudget = () => spent > MAX_RULE_SCAN_MS || budget.exhausted(ctx.fs);
    for (const [index, entry] of entries.entries()) {
      if (overBudget()) {
        unfinished += entries.length - index;
        break;
      }
      let content: string;
      if (entry.content !== null) {
        content = entry.content;
      } else {
        try {
          content = await ctx.fs.readFile(entry.filePath);
        } catch {
          continue;
        }
      }
      const filePath = entry.filePath;

      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (overBudget()) {
          unfinished++;
          break;
        }
        // Input is capped so even a slow pattern stays bounded (regex-safety.ts)
        const started = performance.now();
        const match = re.exec(ruleInput(lines[i]));
        const took = performance.now() - started;
        spent += took;
        budget.add(ctx.fs, took);
        if (match) {
          // The line is quoted from the user's file: credentials on it are masked
          // (masked whole, then cut: a cut-off credential still reads as one)
          const snippet = truncateSnippet(maskCredentialsInLine(ruleInput(lines[i].trim())), 120);
          // a match the masking removed from the line is (part of) a credential
          const matched = snippet.includes(match[0]) ? match[0] : '***';
          evidence.push({
            file: filePath,
            line: i + 1,
            snippet,
            detail: interpolateMessage(msgTemplate, {
              file: filePath,
              line: String(i + 1),
              snippet,
              match: matched,
            }),
          });
        }
      }
    }

    return {
      id: rule.id,
      name: rule.name,
      category: rule.category,
      severity: rule.severity,
      passed: evidence.length === 0 && unfinished === 0,
      message: (evidence.length === 0
        ? `${rule.name}: no matches found`
        : `${rule.name}: ${evidence.length} match(es) — ${rule.description}`)
        + (unfinished > 0 ? unfinishedNote(unfinished, 'file(s)', spent <= MAX_RULE_SCAN_MS) : ''),
      evidence: evidence.length > 0 ? evidence : undefined,
      ...(unfinished > 0 ? { errored: true } : {}),
      fixable: false,
      fixDescription: rule.fix?.guidance,
    };
  };
}

function compileFileExistsRule(rule: DeclarativeRule): CheckModule['run'] {
  const { file_exists } = rule;
  if (!file_exists) throw new Error('No file_exists block');
  const passWhen = file_exists.pass_when ?? 'not-exists';

  return async (ctx: ScanContext): Promise<CheckResult> => {
    const targetPath = file_exists.path.startsWith('/')
      ? file_exists.path
      : resolve(join(ctx.installation.installDir, file_exists.path));

    const exists = await pathExists(targetPath, ctx.fs);
    const passed = passWhen === 'exists' ? exists : !exists;

    const evidence: Evidence[] = passed ? [] : [{
      file: targetPath,
      detail: exists ? 'File exists but should not' : 'File does not exist but should',
    }];

    return {
      id: rule.id,
      name: rule.name,
      category: rule.category,
      severity: rule.severity,
      passed,
      message: passed
        ? `${rule.name}: passed`
        : `${rule.name}: ${rule.description}`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: rule.fix?.guidance,
    };
  };
}

function compileFix(rule: DeclarativeRule): CheckModule['fix'] | undefined {
  if (!rule.fix?.set) return undefined;

  const { set: keyPath, value } = rule.fix;
  return async (ctx: ScanContext): Promise<FixResult> => {
    let applied = false;
    const refused: string[] = [];
    for (const cfg of ctx.configs) {
      // Only the configs the rule failed on — a config rule's check, re-run
      // here; never a file the finding didn't name (a Hermes .env gaining
      // `approvals.mode=manual`). A .env file is flat: a dotted key has no
      // variable to set.
      if (rule.config && !configFails(rule.config, cfg).failed) continue;
      if (cfg.format === 'env' && keyPath.includes('.')) continue;
      try {
        await updateConfigValue(cfg, keyPath, value);
        applied = true;
      } catch (err) {
        // the other configs are still written; say why this one wasn't
        refused.push(err instanceof Error ? err.message : String(err));
      }
    }
    const why = refused.length > 0 ? ` — not changed: ${refused[0]}${refused.length > 1 ? ` (and ${refused.length - 1} more)` : ''}` : '';
    return {
      checkId: rule.id,
      applied,
      message: applied
        ? `Set ${keyPath} to ${JSON.stringify(value)}${why}`
        : `Could not apply fix for ${rule.id}${why}`,
    };
  };
}

/**
 * Compile a validated DeclarativeRule into a CheckModule.
 */
export function compileRule(rule: DeclarativeRule, budget = new RuleTimeBudget()): CheckModule {
  let run: CheckModule['run'];

  if (rule.config) {
    run = compileConfigRule(rule, budget);
  } else if (rule.pattern) {
    run = compilePatternRule(rule, budget);
  } else if (rule.file_exists) {
    run = compileFileExistsRule(rule);
  } else {
    throw new Error(`Rule ${rule.id}: no rule type (config, pattern, file_exists)`);
  }

  return {
    id: rule.id,
    name: rule.name,
    category: rule.category,
    severity: rule.severity,
    description: rule.description,
    supportedAgents: rule.agents,
    supportedPlatforms: rule.platforms,
    run,
    fix: compileFix(rule),
  };
}
