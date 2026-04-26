import { describe, it, expect, vi } from 'vitest';
import { defineCheck } from './check-builder.js';
import type { ScanContext, Evidence } from './types.js';

const minimalCtx = {} as ScanContext;

describe('defineCheck', () => {
  it('returns a CheckModule with the passed-through metadata', () => {
    const check = defineCheck({
      id: 'TEST-001',
      name: 'Test',
      category: 'config',
      severity: 'warning',
      description: 'a test',
      supportedAgents: ['openclaw'],
      run: async (_ctx, h) => h.passed('ok'),
    });
    expect(check.id).toBe('TEST-001');
    expect(check.name).toBe('Test');
    expect(check.category).toBe('config');
    expect(check.severity).toBe('warning');
    expect(check.description).toBe('a test');
    expect(check.supportedAgents).toEqual(['openclaw']);
  });

  it('attaches the fix function when provided', () => {
    const fix = vi.fn();
    const check = defineCheck({
      id: 'T', name: 'T', category: 'config', severity: 'warning', description: '',
      run: async (_c, h) => h.passed('ok'),
      fix,
    });
    expect(check.fix).toBe(fix);
  });

  it('omits fix when not provided', () => {
    const check = defineCheck({
      id: 'T', name: 'T', category: 'config', severity: 'warning', description: '',
      run: async (_c, h) => h.passed('ok'),
    });
    expect(check.fix).toBeUndefined();
  });

  describe('helpers.passed', () => {
    it('returns a passing result with the given message', async () => {
      const check = defineCheck({
        id: 'P', name: 'P', category: 'config', severity: 'warning', description: '',
        run: async (_c, h) => h.passed('all good'),
      });
      const r = await check.run(minimalCtx);
      expect(r).toEqual({
        id: 'P', name: 'P', category: 'config', severity: 'warning',
        passed: true, message: 'all good',
        evidence: undefined, fixable: undefined, fixDescription: undefined,
      });
    });
  });

  describe('helpers.result', () => {
    it('inherits id/name/category/severity from the module', async () => {
      const check = defineCheck({
        id: 'R', name: 'R', category: 'mcp', severity: 'critical', description: '',
        run: async (_c, h) => h.result({ passed: false, message: 'bad' }),
      });
      const r = await check.run(minimalCtx);
      expect(r.id).toBe('R');
      expect(r.category).toBe('mcp');
      expect(r.severity).toBe('critical');
    });

    it('allows severity override (for dynamic-severity checks like MCP-008)', async () => {
      const check = defineCheck({
        id: 'R', name: 'R', category: 'mcp', severity: 'warning', description: '',
        run: async (_c, h) => h.result({ passed: false, message: 'bad', severity: 'critical' }),
      });
      const r = await check.run(minimalCtx);
      expect(r.severity).toBe('critical');
    });

    it('returns evidence: undefined when given an empty array', async () => {
      const check = defineCheck({
        id: 'R', name: 'R', category: 'config', severity: 'warning', description: '',
        run: async (_c, h) => h.result({ passed: true, message: 'ok', evidence: [] }),
      });
      const r = await check.run(minimalCtx);
      expect(r.evidence).toBeUndefined();
    });

    it('forwards a non-empty evidence array verbatim', async () => {
      const ev: Evidence[] = [{ file: '/x', detail: 'thing' }];
      const check = defineCheck({
        id: 'R', name: 'R', category: 'config', severity: 'warning', description: '',
        run: async (_c, h) => h.result({ passed: false, message: 'bad', evidence: ev }),
      });
      const r = await check.run(minimalCtx);
      expect(r.evidence).toEqual(ev);
    });

    it('forwards fixable + fixDescription', async () => {
      const check = defineCheck({
        id: 'R', name: 'R', category: 'config', severity: 'warning', description: '',
        run: async (_c, h) => h.result({ passed: false, message: 'bad', fixable: true, fixDescription: 'do X' }),
      });
      const r = await check.run(minimalCtx);
      expect(r.fixable).toBe(true);
      expect(r.fixDescription).toBe('do X');
    });
  });

  describe('helpers.fromEvidence', () => {
    it('passes when evidence is empty, using the passed message', async () => {
      const check = defineCheck({
        id: 'F', name: 'F', category: 'config', severity: 'warning', description: '',
        run: async (_c, h) => h.fromEvidence([], { passed: 'all clean', failed: (n) => `${n} bad` }),
      });
      const r = await check.run(minimalCtx);
      expect(r.passed).toBe(true);
      expect(r.message).toBe('all clean');
      expect(r.evidence).toBeUndefined();
    });

    it('fails with the templated message when evidence has entries', async () => {
      const ev: Evidence[] = [{ file: '/a' }, { file: '/b' }];
      const check = defineCheck({
        id: 'F', name: 'F', category: 'config', severity: 'warning', description: '',
        run: async (_c, h) => h.fromEvidence(ev, { passed: 'ok', failed: (n) => `Found ${n} issues` }),
      });
      const r = await check.run(minimalCtx);
      expect(r.passed).toBe(false);
      expect(r.message).toBe('Found 2 issues');
      expect(r.evidence).toEqual(ev);
    });

    it('forwards severity override through fromEvidence', async () => {
      const ev: Evidence[] = [{ file: '/x' }];
      const check = defineCheck({
        id: 'F', name: 'F', category: 'mcp', severity: 'warning', description: '',
        run: async (_c, h) => h.fromEvidence(ev, {
          passed: 'ok', failed: () => 'bad', severity: 'critical',
        }),
      });
      const r = await check.run(minimalCtx);
      expect(r.severity).toBe('critical');
    });
  });
});
