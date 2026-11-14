import type { Operator } from './operators.js';
import { VALID_OPERATORS } from './operators.js';
import type { CheckCategory, AgentType, Severity, Platform } from '../core/types.js';
import { AGENT_TYPES, CHECK_CATEGORIES } from '../core/types.js';
import { unsafeRegexReason } from './regex-safety.js';
import { escapeControlChars } from '../reporting/text-safety.js';
import { keySegments } from '../core/utils.js';

const VALID_CATEGORIES: readonly string[] = CHECK_CATEGORIES;

const VALID_AGENTS: readonly string[] = AGENT_TYPES;

const VALID_SEVERITIES: readonly string[] = ['critical', 'warning', 'info'];

const VALID_TARGETS: readonly string[] = ['configs', 'skills', 'all'];

/** Values of `process.platform` (core/types.ts Platform). */
const VALID_PLATFORMS: readonly string[] = ['aix', 'android', 'darwin', 'freebsd', 'haiku', 'linux', 'openbsd', 'sunos', 'win32', 'cygwin', 'netbsd'];

/**
 * A rule ID is printed in every report format and in terminal warnings, and is
 * SARIF's ruleId: letters, digits, `.`, `_`, `-` — no control characters,
 * spaces or markup.
 */
const RULE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * Key path segments that reach an object's prototype instead of a config
 * key: `fix.set: __proto__.polluted` would change every object in VASO.
 */
const PROTOTYPE_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

/** One display line of rule text: control characters shown escaped. */
const line = (s: string) => escapeControlChars(s, { lineBreaks: true });

/** Raw shape of a config rule block in YAML. */
export interface RawConfigRule {
  path: string;
  operator: Operator;
  value?: unknown;
  pass_when?: 'match' | 'no-match';
}

/** Raw shape of a pattern rule block in YAML. */
export interface RawPatternRule {
  regex: string;
  target?: 'configs' | 'skills' | 'all';
  message?: string;
}

/** Raw shape of a file_exists rule block in YAML. */
export interface RawFileExistsRule {
  path: string;
  pass_when?: 'exists' | 'not-exists';
}

/** Raw shape of a fix block in YAML. */
export interface RawFix {
  set?: string;
  value?: unknown;
  guidance?: string;
}

/** A validated declarative rule. */
export interface DeclarativeRule {
  id: string;
  name: string;
  category: CheckCategory;
  severity: Severity;
  description: string;
  agents?: AgentType[];
  platforms?: Platform[];
  config?: RawConfigRule;
  pattern?: RawPatternRule;
  file_exists?: RawFileExistsRule;
  fix?: RawFix;
}

export interface ValidationError {
  rule?: string;
  field?: string;
  message: string;
}

/** Why a rule regex can't be used (invalid, or able to backtrack super-linearly). */
function regexError(source: string): string | undefined {
  try {
    new RegExp(source);
  } catch {
    return 'the regular expression is not valid';
  }
  const unsafe = unsafeRegexReason(source);
  return unsafe ? `the regular expression can backtrack super-linearly: ${unsafe}` : undefined;
}

/**
 * Validate a parsed YAML document (expected shape: { rules: [...] }).
 * Returns validated rules and any errors encountered.
 */
export function validateRuleFile(data: unknown): { rules: DeclarativeRule[]; errors: ValidationError[] } {
  const errors: ValidationError[] = [];
  const rules: DeclarativeRule[] = [];

  if (!data || typeof data !== 'object') {
    errors.push({ message: 'Rule file must be a YAML object with a "rules" array' });
    return { rules, errors };
  }

  const doc = data as Record<string, unknown>;
  if (!Array.isArray(doc.rules)) {
    errors.push({ message: 'Rule file must contain a "rules" array at the top level' });
    return { rules, errors };
  }

  for (let i = 0; i < doc.rules.length; i++) {
    const raw = doc.rules[i];
    // Printed in warnings before the ID is validated
    const rawId = raw?.id ? String(raw.id) : '';
    const label = rawId ? line(rawId.length > 80 ? `${rawId.slice(0, 80)}…` : rawId) : `rules[${i}]`;

    if (!raw || typeof raw !== 'object') {
      errors.push({ rule: label, message: 'Rule must be an object' });
      continue;
    }

    const r = raw as Record<string, unknown>;
    const ruleErrors: ValidationError[] = [];

    // Required string fields
    for (const field of ['id', 'name', 'description'] as const) {
      if (typeof r[field] !== 'string' || (r[field] as string).trim() === '') {
        ruleErrors.push({ rule: label, field, message: `"${field}" is required and must be a non-empty string` });
      }
    }
    if (typeof r.id === 'string' && r.id.trim() !== '' && !RULE_ID_RE.test(r.id)) {
      ruleErrors.push({ rule: label, field: 'id', message: '"id" must be 1–64 letters, digits, ".", "_" or "-", starting with a letter or digit' });
    }

    // Category
    if (!VALID_CATEGORIES.includes(r.category as string)) {
      ruleErrors.push({ rule: label, field: 'category', message: `"category" must be one of: ${VALID_CATEGORIES.join(', ')}` });
    }

    // Severity
    if (!VALID_SEVERITIES.includes(r.severity as string)) {
      ruleErrors.push({ rule: label, field: 'severity', message: `"severity" must be one of: ${VALID_SEVERITIES.join(', ')}` });
    }

    // Optional agents array
    if (r.agents !== undefined) {
      if (!Array.isArray(r.agents) || !r.agents.every(a => VALID_AGENTS.includes(a as string))) {
        ruleErrors.push({ rule: label, field: 'agents', message: `"agents" must be an array of valid agent types: ${VALID_AGENTS.join(', ')}` });
      }
    }

    // Optional platforms array
    if (r.platforms !== undefined) {
      if (!Array.isArray(r.platforms) || !r.platforms.every(p => VALID_PLATFORMS.includes(p as string))) {
        ruleErrors.push({ rule: label, field: 'platforms', message: `"platforms" must be an array of: ${VALID_PLATFORMS.join(', ')}` });
      }
    }

    // Exactly one rule type
    const hasConfig = r.config !== undefined;
    const hasPattern = r.pattern !== undefined;
    const hasFileExists = r.file_exists !== undefined;
    const typeCount = [hasConfig, hasPattern, hasFileExists].filter(Boolean).length;

    if (typeCount !== 1) {
      ruleErrors.push({ rule: label, message: 'Rule must have exactly one of: "config", "pattern", "file_exists"' });
    }

    // Validate config block
    if (hasConfig) {
      const c = r.config as Record<string, unknown>;
      if (!c || typeof c !== 'object') {
        ruleErrors.push({ rule: label, field: 'config', message: '"config" must be an object' });
      } else {
        if (typeof c.path !== 'string' || c.path.trim() === '') {
          ruleErrors.push({ rule: label, field: 'config.path', message: '"config.path" is required' });
        }
        if (!VALID_OPERATORS.includes(c.operator as Operator)) {
          ruleErrors.push({ rule: label, field: 'config.operator', message: `"config.operator" must be one of: ${VALID_OPERATORS.join(', ')}` });
        }
        if (c.operator === 'matches') {
          const reason = typeof c.value !== 'string' ? '"config.value" must be a regular expression string for "matches"'
            : c.value.length > 500 ? '"config.value" must be 500 characters or less'
            : regexError(c.value);
          if (reason) ruleErrors.push({ rule: label, field: 'config.value', message: reason });
        }
        if (c.pass_when !== undefined && c.pass_when !== 'match' && c.pass_when !== 'no-match') {
          ruleErrors.push({ rule: label, field: 'config.pass_when', message: '"config.pass_when" must be "match" or "no-match"' });
        }
      }
    }

    // Validate pattern block
    if (hasPattern) {
      const p = r.pattern as Record<string, unknown>;
      if (!p || typeof p !== 'object') {
        ruleErrors.push({ rule: label, field: 'pattern', message: '"pattern" must be an object' });
      } else {
        if (typeof p.regex !== 'string' || p.regex.trim() === '') {
          ruleErrors.push({ rule: label, field: 'pattern.regex', message: '"pattern.regex" is required' });
        } else if (p.regex.length > 500) {
          ruleErrors.push({ rule: label, field: 'pattern.regex', message: '"pattern.regex" must be 500 characters or less' });
        } else {
          const reason = regexError(p.regex);
          if (reason) ruleErrors.push({ rule: label, field: 'pattern.regex', message: reason.replace('the regular expression', '"pattern.regex"') });
        }
        if (p.target !== undefined && !VALID_TARGETS.includes(p.target as string)) {
          ruleErrors.push({ rule: label, field: 'pattern.target', message: `"pattern.target" must be one of: ${VALID_TARGETS.join(', ')}` });
        }
        if (p.message !== undefined && typeof p.message !== 'string') {
          ruleErrors.push({ rule: label, field: 'pattern.message', message: '"pattern.message" must be a string' });
        }
      }
    }

    // Validate file_exists block
    if (hasFileExists) {
      const f = r.file_exists as Record<string, unknown>;
      if (!f || typeof f !== 'object') {
        ruleErrors.push({ rule: label, field: 'file_exists', message: '"file_exists" must be an object' });
      } else {
        if (typeof f.path !== 'string' || f.path.trim() === '') {
          ruleErrors.push({ rule: label, field: 'file_exists.path', message: '"file_exists.path" is required' });
        }
        if (f.pass_when !== undefined && f.pass_when !== 'exists' && f.pass_when !== 'not-exists') {
          ruleErrors.push({ rule: label, field: 'file_exists.pass_when', message: '"file_exists.pass_when" must be "exists" or "not-exists"' });
        }
      }
    }

    // Validate fix block
    if (r.fix !== undefined) {
      const f = r.fix as Record<string, unknown>;
      if (!f || typeof f !== 'object') {
        ruleErrors.push({ rule: label, field: 'fix', message: '"fix" must be an object' });
      } else {
        const hasSet = f.set !== undefined;
        const hasGuidance = f.guidance !== undefined;
        if (!hasSet && !hasGuidance) {
          ruleErrors.push({ rule: label, field: 'fix', message: '"fix" must have either "set" + "value" or "guidance"' });
        }
        if (hasSet && typeof f.set !== 'string') {
          ruleErrors.push({ rule: label, field: 'fix.set', message: '"fix.set" must be a string (config path)' });
        } else if (hasSet && (f.set as string).trim() === '') {
          ruleErrors.push({ rule: label, field: 'fix.set', message: '"fix.set" must name a config key' });
        } else if (hasSet && keySegments(f.set as string).some(k => PROTOTYPE_KEYS.has(k))) {
          ruleErrors.push({ rule: label, field: 'fix.set', message: '"fix.set" may not name __proto__, prototype or constructor' });
        }
        if (hasGuidance && typeof f.guidance !== 'string') {
          ruleErrors.push({ rule: label, field: 'fix.guidance', message: '"fix.guidance" must be a string' });
        }
      }
    }

    if (ruleErrors.length > 0) {
      errors.push(...ruleErrors);
    } else {
      // Rule text is shown in terminals and reports: control characters escaped
      const pattern = r.pattern as RawPatternRule | undefined;
      const fix = r.fix as RawFix | undefined;
      rules.push({
        id: r.id as string,
        name: line(r.name as string),
        category: r.category as CheckCategory,
        severity: r.severity as Severity,
        description: escapeControlChars(r.description as string),
        agents: r.agents as AgentType[] | undefined,
        platforms: r.platforms as Platform[] | undefined,
        config: r.config as RawConfigRule | undefined,
        pattern: pattern?.message !== undefined ? { ...pattern, message: escapeControlChars(pattern.message) } : pattern,
        file_exists: r.file_exists as RawFileExistsRule | undefined,
        fix: fix?.guidance !== undefined ? { ...fix, guidance: escapeControlChars(fix.guidance) } : fix,
      });
    }
  }

  return { rules, errors };
}
