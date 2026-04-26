import { describe, it, expect } from 'vitest';
import { JunitReporter } from './junit.js';
import type { ScanResult } from '../core/types.js';

function makeScanResult(overrides?: Partial<ScanResult>): ScanResult {
  return {
    timestamp: '2026-02-21T12:00:00.000Z',
    agents: [{
      agent: 'openclaw',
      installation: { agent: 'openclaw', installDir: '/x', configFiles: [] },
      results: [
        {
          id: 'CFG-001', name: 'Gateway Binding', category: 'config', severity: 'critical',
          passed: false, message: 'Gateway bound to 0.0.0.0',
          evidence: [{ file: '/x/config.yaml', line: 12, snippet: 'host: 0.0.0.0' }],
        },
        {
          id: 'CFG-002', name: 'API Key Exposure', category: 'config', severity: 'critical',
          passed: true, message: 'No API keys found',
        },
      ],
      score: 65, grade: 'C',
    }],
    totalScore: 65, totalGrade: 'C',
    summary: { critical: 1, warning: 0, info: 0, passed: 1, total: 2 },
    ...overrides,
  };
}

describe('JunitReporter', () => {
  it('has format set to junit', () => {
    expect(new JunitReporter().format).toBe('junit');
  });

  it('emits an XML prolog and a testsuites root', () => {
    const out = new JunitReporter().render(makeScanResult());
    expect(out.startsWith('<?xml version="1.0" encoding="UTF-8"?>')).toBe(true);
    expect(out).toContain('<testsuites ');
    expect(out).toContain('</testsuites>');
  });

  it('totals tests and failures across the suite', () => {
    const out = new JunitReporter().render(makeScanResult());
    expect(out).toMatch(/<testsuites[^>]*tests="2"/);
    expect(out).toMatch(/<testsuites[^>]*failures="1"/);
    expect(out).toMatch(/<testsuites[^>]*errors="0"/);
  });

  it('emits one testsuite per agent with per-agent counts', () => {
    const out = new JunitReporter().render(makeScanResult());
    expect(out).toMatch(/<testsuite[^>]*name="openclaw"/);
    expect(out).toMatch(/<testsuite[^>]*tests="2"/);
    expect(out).toMatch(/<testsuite[^>]*failures="1"/);
  });

  it('failing checks emit a failure element with severity as type', () => {
    const out = new JunitReporter().render(makeScanResult());
    expect(out).toContain('<testcase ');
    expect(out).toContain('classname="openclaw.config"');
    expect(out).toContain('name="CFG-001 — Gateway Binding"');
    expect(out).toMatch(/<failure[^>]*type="critical"/);
    expect(out).toContain('Gateway bound to 0.0.0.0');
  });

  it('passing checks have no failure element', () => {
    const out = new JunitReporter().render(makeScanResult());
    // CFG-002 passes; check it appears as a self-closing or empty testcase
    expect(out).toMatch(/<testcase[^>]*name="CFG-002[^"]*"><\/testcase>/);
  });

  it('escapes XML metacharacters in messages and evidence', () => {
    const result = makeScanResult({
      agents: [{
        agent: 'openclaw',
        installation: { agent: 'openclaw', installDir: '/x', configFiles: [] },
        results: [{
          id: 'X', name: 'name with <brackets> & "quotes"', category: 'config', severity: 'warning',
          passed: false, message: 'message with <html> & "quoted"',
          evidence: [{ file: '/x', detail: 'a > b && c < d' }],
        }],
        score: 50, grade: 'D',
      }],
    });
    const out = new JunitReporter().render(result);
    expect(out).toContain('&lt;brackets&gt;');
    expect(out).toContain('&amp;');
    expect(out).toContain('&quot;quotes&quot;');
    expect(out).toContain('a &gt; b &amp;&amp; c &lt; d');
    expect(out).not.toMatch(/[^&]"quoted"/); // no unescaped quoted
  });

  it('agent label includes the per-agent name when present', () => {
    const result = makeScanResult();
    result.agents[0].installation.agentName = 'subagent-a';
    const out = new JunitReporter().render(result);
    expect(out).toContain('name="openclaw.subagent-a"');
    expect(out).toContain('classname="openclaw.subagent-a.config"');
  });

  it('handles an empty agents array', () => {
    const out = new JunitReporter().render(makeScanResult({
      agents: [],
      totalScore: 100, totalGrade: 'A',
      summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
    }));
    expect(out).toMatch(/<testsuites[^>]*tests="0"/);
    expect(out).toMatch(/<testsuites[^>]*failures="0"/);
    expect(out).not.toContain('<testsuite ');
  });
});
