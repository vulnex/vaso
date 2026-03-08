import { describe, it, expect } from 'vitest';
import { validateRuleFile } from './schema.js';

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
