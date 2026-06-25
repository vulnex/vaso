import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import chalk from 'chalk';
import { TerminalReporter } from './terminal.js';
import type { ScanResult } from '../core/types.js';

function makeScanResult(overrides?: Partial<ScanResult>): ScanResult {
  return {
    timestamp: '2026-02-21T12:00:00.000Z',
    agents: [{
      agent: 'openclaw',
      installation: {
        agent: 'openclaw',
        installDir: '/home/user/.openclaw',
        configFiles: [],
        user: 'testuser',
        profile: 'default',
      },
      results: [
        {
          id: 'CFG-001',
          name: 'Gateway Binding',
          category: 'config',
          severity: 'critical',
          passed: false,
          message: 'Gateway bound to 0.0.0.0',
          evidence: [{ file: '/home/user/.openclaw/config.yaml', line: 12, snippet: 'host: 0.0.0.0' }],
          fixable: true,
          fixDescription: 'Bind to 127.0.0.1',
        },
        {
          id: 'CFG-003',
          name: 'TLS Disabled',
          category: 'config',
          severity: 'warning',
          passed: false,
          message: 'TLS is not enabled',
        },
        {
          id: 'CFG-005',
          name: 'Prompt Injection',
          category: 'config',
          severity: 'info',
          passed: false,
          message: 'Prompt injection detection not configured',
        },
        {
          id: 'CFG-002',
          name: 'API Key Exposure',
          category: 'config',
          severity: 'critical',
          passed: true,
          message: 'No API keys found in config',
        },
      ],
      score: 65,
      grade: 'C',
    }],
    totalScore: 65,
    totalGrade: 'C',
    fleetAverage: 65,
    summary: { critical: 1, warning: 1, info: 1, passed: 1, total: 4 },
    ...overrides,
  };
}

let savedChalkLevel: number;

describe('TerminalReporter', () => {
  beforeAll(() => {
    savedChalkLevel = chalk.level;
    chalk.level = 0;
  });

  afterAll(() => {
    chalk.level = savedChalkLevel;
  });

  it('has format property set to terminal', () => {
    const reporter = new TerminalReporter();
    expect(reporter.format).toBe('terminal');
  });

  it('includes header with timestamp', () => {
    const reporter = new TerminalReporter();
    const output = reporter.render(makeScanResult());
    expect(output).toContain('VASO Security Scan Report');
    expect(output).toContain('2026-02-21T12:00:00.000Z');
  });

  it('shows agent info with score and grade', () => {
    const reporter = new TerminalReporter();
    const output = reporter.render(makeScanResult());
    expect(output).toContain('Agent: openclaw');
    expect(output).toContain('65');
    expect(output).toContain('C');
  });

  it('shows failed findings', () => {
    const reporter = new TerminalReporter();
    const output = reporter.render(makeScanResult());
    expect(output).toContain('Findings:');
    expect(output).toContain('CFG-001');
    expect(output).toContain('Gateway Binding');
    expect(output).toContain('Gateway bound to 0.0.0.0');
  });

  it('shows passed checks', () => {
    const reporter = new TerminalReporter();
    const output = reporter.render(makeScanResult());
    expect(output).toContain('Passed:');
    expect(output).toContain('CFG-002');
    expect(output).toContain('API Key Exposure');
  });

  it('shows no agents message when empty', () => {
    const reporter = new TerminalReporter();
    const output = reporter.render(makeScanResult({
      agents: [],
      totalScore: 100,
      totalGrade: 'A',
      fleetAverage: 100,
      summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
    }));
    expect(output).toContain('No agents detected');
  });

  it('renders evidence with file and line', () => {
    const reporter = new TerminalReporter();
    const output = reporter.render(makeScanResult());
    expect(output).toContain('/home/user/.openclaw/config.yaml');
    expect(output).toContain(':12');
    expect(output).toContain('host: 0.0.0.0');
  });

  it('shows fixable hint', () => {
    const reporter = new TerminalReporter();
    const output = reporter.render(makeScanResult());
    expect(output).toContain('Fixable:');
    expect(output).toContain('Bind to 127.0.0.1');
  });

  it('includes summary counts', () => {
    const reporter = new TerminalReporter();
    const output = reporter.render(makeScanResult());
    expect(output).toContain('Summary');
    expect(output).toContain('Agents scanned: 1');
    expect(output).toContain('Total checks: 4');
  });

  it('shows user and profile metadata', () => {
    const reporter = new TerminalReporter();
    const output = reporter.render(makeScanResult());
    expect(output).toContain('testuser');
    expect(output).toContain('default');
  });
});
