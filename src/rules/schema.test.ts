import { describe, it, expect } from 'vitest';
import { validateRuleFile } from './schema.js';
import { AGENT_TYPES, CHECK_CATEGORIES } from '../core/types.js';

describe('validateRuleFile: identifiers, platforms, fix paths, display text', () => {
  const base = { name: 'n', category: 'config', severity: 'info', description: 'd', config: { path: 'a', operator: 'exists' } };
  const check = (rule: Record<string, unknown>) => validateRuleFile({ rules: [{ ...base, ...rule }] });

  it('accepts identifier-shaped ids only', () => {
    expect(check({ id: 'ORG-001' }).errors).toEqual([]);
    expect(check({ id: 'org.rule_2' }).errors).toEqual([]);
    for (const id of ['A\u001b[2JB', 'has space', '-lead', 'X'.repeat(65), 'a<b>']) {
      expect(check({ id }).errors.some(e => e.field === 'id')).toBe(true);
    }
    // the label in the error is printable
    expect(check({ id: 'A\u001b[2JB' }).errors[0].rule).toBe('A\\x1b[2JB');
  });

  it('accepts only platform names VASO knows', () => {
    expect(check({ id: 'P-1', platforms: ['linux', 'darwin'] }).errors).toEqual([]);
    expect(check({ id: 'P-2', platforms: ['macos'] }).errors.some(e => e.field === 'platforms')).toBe(true);
  });

  it('rejects a fix.set path through the prototype', () => {
    for (const set of ['__proto__.x', 'a.constructor.prototype', '']) {
      expect(check({ id: 'F-1', fix: { set, value: 1 } }).errors.some(e => e.field === 'fix.set')).toBe(true);
    }
    expect(check({ id: 'F-2', fix: { set: 'server.debug', value: false } }).errors).toEqual([]);
  });

  it('rejects a fix.set path with an empty segment', () => {
    for (const set of ['model..x', '.model', 'model.', 'a. .b']) {
      expect(check({ id: 'F-3', fix: { set, value: 1 } }).errors.some(e => e.field === 'fix.set' && /empty key segment/.test(e.message))).toBe(true);
    }
  });

  it('escapes control characters in names, descriptions and messages', () => {
    const { rules } = check({ id: 'T-1', name: 'a\u001b]0;x\u0007\nb', description: 'line1\nline2‮', fix: { guidance: 'g\u001b[2J' } });
    expect(rules[0].name).toBe('a\\x1b]0;x\\x07\\nb');
    expect(rules[0].description).toBe('line1\nline2\\u202e');
    expect(rules[0].fix?.guidance).toBe('g\\x1b[2J');
  });
});

describe('validateRuleFile', () => {
  it('validates a correct config rule', () => {
    const { rules, errors } = validateRuleFile({
      rules: [{
        id: 'TEST-001',
        name: 'Test rule',
        category: 'config',
        severity: 'warning',
        description: 'A test rule',
        config: { path: 'server.debug', operator: 'eq', value: true },
      }],
    });

    expect(errors).toHaveLength(0);
    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe('TEST-001');
    expect(rules[0].config?.operator).toBe('eq');
  });

  it('validates a correct pattern rule', () => {
    const { rules, errors } = validateRuleFile({
      rules: [{
        id: 'TEST-002',
        name: 'Pattern test',
        category: 'config',
        severity: 'critical',
        description: 'Find secrets',
        pattern: { regex: 'AKIA[0-9A-Z]{16}', target: 'configs' },
      }],
    });

    expect(errors).toHaveLength(0);
    expect(rules).toHaveLength(1);
    expect(rules[0].pattern?.regex).toBe('AKIA[0-9A-Z]{16}');
  });

  it('validates a correct file_exists rule', () => {
    const { rules, errors } = validateRuleFile({
      rules: [{
        id: 'TEST-003',
        name: 'No .env',
        category: 'config',
        severity: 'warning',
        description: 'Env file check',
        file_exists: { path: '.env', pass_when: 'not-exists' },
      }],
    });

    expect(errors).toHaveLength(0);
    expect(rules).toHaveLength(1);
  });

  it('rejects missing required fields', () => {
    const { rules, errors } = validateRuleFile({
      rules: [{ id: '', category: 'bogus', severity: 'bogus' }],
    });

    expect(rules).toHaveLength(0);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors.some(e => e.field === 'id')).toBe(true);
    expect(errors.some(e => e.field === 'category')).toBe(true);
    expect(errors.some(e => e.field === 'severity')).toBe(true);
  });

  it('rejects rule with no type block', () => {
    const { errors } = validateRuleFile({
      rules: [{
        id: 'TEST-X',
        name: 'No type',
        category: 'config',
        severity: 'info',
        description: 'Missing type',
      }],
    });

    expect(errors.some(e => e.message.includes('exactly one of'))).toBe(true);
  });

  it('rejects rule with multiple type blocks', () => {
    const { errors } = validateRuleFile({
      rules: [{
        id: 'TEST-X',
        name: 'Multi type',
        category: 'config',
        severity: 'info',
        description: 'Two types',
        config: { path: 'a', operator: 'eq', value: 1 },
        pattern: { regex: 'x' },
      }],
    });

    expect(errors.some(e => e.message.includes('exactly one of'))).toBe(true);
  });

  it('rejects invalid operator in config rule', () => {
    const { errors } = validateRuleFile({
      rules: [{
        id: 'TEST-X',
        name: 'Bad op',
        category: 'config',
        severity: 'info',
        description: 'Invalid operator',
        config: { path: 'a', operator: 'nope' },
      }],
    });

    expect(errors.some(e => e.field === 'config.operator')).toBe(true);
  });

  it('rejects invalid regex in pattern rule', () => {
    const { errors } = validateRuleFile({
      rules: [{
        id: 'TEST-X',
        name: 'Bad regex',
        category: 'config',
        severity: 'info',
        description: 'Invalid regex',
        pattern: { regex: '[invalid' },
      }],
    });

    expect(errors.some(e => e.field === 'pattern.regex')).toBe(true);
  });

  it('rejects overly long regex', () => {
    const { errors } = validateRuleFile({
      rules: [{
        id: 'TEST-X',
        name: 'Long regex',
        category: 'config',
        severity: 'info',
        description: 'Too long',
        pattern: { regex: 'a'.repeat(501) },
      }],
    });

    expect(errors.some(e => e.message.includes('500 characters'))).toBe(true);
  });

  it('rejects invalid pattern target', () => {
    const { errors } = validateRuleFile({
      rules: [{
        id: 'TEST-X',
        name: 'Bad target',
        category: 'config',
        severity: 'info',
        description: 'Bad target',
        pattern: { regex: 'a', target: 'invalid' },
      }],
    });

    expect(errors.some(e => e.field === 'pattern.target')).toBe(true);
  });

  it('validates optional agents filter', () => {
    const { rules, errors } = validateRuleFile({
      rules: [{
        id: 'TEST-A',
        name: 'With agents',
        category: 'config',
        severity: 'info',
        description: 'Filter by agent',
        agents: ['openclaw', 'nanoclaw'],
        config: { path: 'a', operator: 'exists' },
      }],
    });

    expect(errors).toHaveLength(0);
    expect(rules[0].agents).toEqual(['openclaw', 'nanoclaw']);
  });

  it('accepts every supported agent and check category', () => {
    for (const agent of AGENT_TYPES) {
      const { errors } = validateRuleFile({
        rules: [{
          id: `AGENT-${agent}`,
          name: `Rule for ${agent}`,
          category: 'config',
          severity: 'info',
          description: 'Agent coverage',
          agents: [agent],
          config: { path: 'a', operator: 'exists' },
        }],
      });
      expect(errors, agent).toHaveLength(0);
    }

    for (const category of CHECK_CATEGORIES) {
      const { errors } = validateRuleFile({
        rules: [{
          id: `CAT-${category}`,
          name: `Rule for ${category}`,
          category,
          severity: 'info',
          description: 'Category coverage',
          config: { path: 'a', operator: 'exists' },
        }],
      });
      expect(errors, category).toHaveLength(0);
    }
  });

  it('rejects invalid agent names', () => {
    const { errors } = validateRuleFile({
      rules: [{
        id: 'TEST-A',
        name: 'Bad agent',
        category: 'config',
        severity: 'info',
        description: 'Unknown agent',
        agents: ['foobar'],
        config: { path: 'a', operator: 'exists' },
      }],
    });

    expect(errors.some(e => e.field === 'agents')).toBe(true);
  });

  it('validates fix with set + value', () => {
    const { rules, errors } = validateRuleFile({
      rules: [{
        id: 'TEST-F',
        name: 'With fix',
        category: 'config',
        severity: 'warning',
        description: 'Fixable',
        config: { path: 'debug', operator: 'eq', value: true },
        fix: { set: 'debug', value: false },
      }],
    });

    expect(errors).toHaveLength(0);
    expect(rules[0].fix?.set).toBe('debug');
    expect(rules[0].fix?.value).toBe(false);
  });

  it('validates fix with guidance', () => {
    const { rules, errors } = validateRuleFile({
      rules: [{
        id: 'TEST-G',
        name: 'With guidance',
        category: 'config',
        severity: 'info',
        description: 'Guidance only',
        config: { path: 'a', operator: 'exists' },
        fix: { guidance: 'Do the thing' },
      }],
    });

    expect(errors).toHaveLength(0);
    expect(rules[0].fix?.guidance).toBe('Do the thing');
  });

  it('rejects fix with neither set nor guidance', () => {
    const { errors } = validateRuleFile({
      rules: [{
        id: 'TEST-X',
        name: 'Bad fix',
        category: 'config',
        severity: 'info',
        description: 'Empty fix',
        config: { path: 'a', operator: 'exists' },
        fix: {},
      }],
    });

    expect(errors.some(e => e.field === 'fix')).toBe(true);
  });

  it('rejects non-object input', () => {
    const { errors } = validateRuleFile('not an object');
    expect(errors).toHaveLength(1);
  });

  it('rejects missing rules array', () => {
    const { errors } = validateRuleFile({ notRules: [] });
    expect(errors).toHaveLength(1);
  });

  it('handles multiple rules with mixed validity', () => {
    const { rules, errors } = validateRuleFile({
      rules: [
        {
          id: 'GOOD-001',
          name: 'Valid',
          category: 'config',
          severity: 'info',
          description: 'Good rule',
          config: { path: 'a', operator: 'exists' },
        },
        { id: 'BAD', severity: 'nope' },
      ],
    });

    expect(rules).toHaveLength(1);
    expect(rules[0].id).toBe('GOOD-001');
    expect(errors.length).toBeGreaterThan(0);
  });

  it('validates file_exists pass_when options', () => {
    const { errors: e1 } = validateRuleFile({
      rules: [{
        id: 'T1', name: 'T', category: 'config', severity: 'info', description: 'D',
        file_exists: { path: 'a', pass_when: 'exists' },
      }],
    });
    expect(e1).toHaveLength(0);

    const { errors: e2 } = validateRuleFile({
      rules: [{
        id: 'T2', name: 'T', category: 'config', severity: 'info', description: 'D',
        file_exists: { path: 'a', pass_when: 'bad' },
      }],
    });
    expect(e2.some(e => e.field === 'file_exists.pass_when')).toBe(true);
  });
});
