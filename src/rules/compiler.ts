import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import type { CheckModule, CheckResult, ScanContext, Evidence, FixResult } from '../core/types.js';
import { getNestedValue } from '../core/utils.js';
import { pathExists } from '../core/utils.js';
import { evaluateOperator } from './operators.js';
import { updateConfigValue } from '../remediation/config-writer.js';
import type { DeclarativeRule } from './schema.js';

function interpolateMessage(template: string, vars: Record<string, string>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, key) => vars[key] ?? '');
}

function compileConfigRule(rule: DeclarativeRule): CheckModule['run'] {
  const { config } = rule;
  if (!config) throw new Error('No config block');

  return async (ctx: ScanContext): Promise<CheckResult> => {
    const evidence: Evidence[] = [];

    for (const cfg of ctx.configs) {
      const actual = getNestedValue(cfg.data, config.path);
      const conditionMatches = evaluateOperator(actual, config.operator, config.value);

      // Default: condition match = fail (detecting the bad thing)
      // pass_when: "match" = condition match means pass
      const passWhen = config.pass_when ?? 'no-match';
      const passed = passWhen === 'match' ? conditionMatches : !conditionMatches;

      if (!passed) {
        evidence.push({
          file: cfg.filePath,
          detail: `${config.path} = ${JSON.stringify(actual)}`,
        });
      }
    }

    return {
      id: rule.id,
      name: rule.name,
      category: rule.category,
      severity: rule.severity,
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? `${rule.name}: passed`
        : `${rule.name}: ${evidence.length} config(s) failed — ${rule.description}`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: rule.fix?.set !== undefined,
      fixDescription: rule.fix?.guidance ?? (rule.fix?.set ? `Set ${rule.fix.set} to ${JSON.stringify(rule.fix.value)}` : undefined),
    };
  };
}

function compilePatternRule(rule: DeclarativeRule): CheckModule['run'] {
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

    for (const entry of entries) {
      let content: string;
      if (entry.content !== null) {
        content = entry.content;
      } else {
        try {
          content = await readFile(entry.filePath, 'utf-8');
        } catch {
          continue;
        }
      }
      const filePath = entry.filePath;

      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const match = re.exec(lines[i]);
        if (match) {
          const snippet = lines[i].trim().slice(0, 120);
          evidence.push({
            file: filePath,
            line: i + 1,
            snippet,
            detail: interpolateMessage(msgTemplate, {
              file: filePath,
              line: String(i + 1),
              snippet,
              match: match[0],
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
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? `${rule.name}: no matches found`
        : `${rule.name}: ${evidence.length} match(es) — ${rule.description}`,
      evidence: evidence.length > 0 ? evidence : undefined,
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

    const exists = await pathExists(targetPath);
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
    for (const cfg of ctx.configs) {
      try {
        await updateConfigValue(cfg, keyPath, value);
        applied = true;
      } catch {
        // skip configs that can't be written
      }
    }
    return {
      checkId: rule.id,
      applied,
      message: applied
        ? `Set ${keyPath} to ${JSON.stringify(value)}`
        : `Could not apply fix for ${rule.id}`,
    };
  };
}

/**
 * Compile a validated DeclarativeRule into a CheckModule.
 */
export function compileRule(rule: DeclarativeRule): CheckModule {
  let run: CheckModule['run'];

  if (rule.config) {
    run = compileConfigRule(rule);
  } else if (rule.pattern) {
    run = compilePatternRule(rule);
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
