import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../core/engine.js', () => ({
  ScanEngine: vi.fn(),
}));

vi.mock('../reporting/index.js', () => ({
  getReporter: vi.fn(),
}));

vi.mock('../core/baseline.js', () => ({
  saveBaseline: vi.fn(),
  loadBaseline: vi.fn(),
  diffResults: vi.fn(),
  BaselineLoadError: class BaselineLoadError extends Error {},
}));

vi.mock('node:fs/promises', () => ({
  writeFile: vi.fn(),
  mkdir: vi.fn().mockResolvedValue(undefined),
}));

import { ScanEngine } from '../core/engine.js';
import { getReporter } from '../reporting/index.js';
import { saveBaseline, loadBaseline, diffResults, BaselineLoadError } from '../core/baseline.js';
import { writeFile, mkdir } from 'node:fs/promises';
import { runScan } from './scan.js';
import type { ScanResult } from '../core/types.js';

const mockScanEngine = vi.mocked(ScanEngine);
const mockGetReporter = vi.mocked(getReporter);
const mockSaveBaseline = vi.mocked(saveBaseline);
const mockLoadBaseline = vi.mocked(loadBaseline);
const mockDiffResults = vi.mocked(diffResults);
const mockWriteFile = vi.mocked(writeFile);
const mockMkdir = vi.mocked(mkdir);

function makeScanResult(overrides?: Partial<ScanResult>): ScanResult {
  return {
    timestamp: '2026-02-21T12:00:00.000Z',
    agents: [{
      agent: 'openclaw',
      installation: { agent: 'openclaw', installDir: '/tmp', configFiles: [] },
      results: [
        { id: 'CFG-001', name: 'Test', category: 'config', severity: 'warning', passed: false, message: 'fail' },
      ],
      score: 80,
      grade: 'B',
    }],
    totalScore: 80,
    totalGrade: 'B',
    fleetAverage: 80,
    summary: { critical: 0, warning: 1, info: 0, passed: 0, total: 1 },
    ...overrides,
  };
}

describe('runScan', () => {
  let consoleLogs: string[];
  let consoleErrors: string[];
  const origExitCode = process.exitCode;

  beforeEach(() => {
    vi.resetAllMocks();
    process.exitCode = undefined;
    consoleLogs = [];
    consoleErrors = [];
    vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
      consoleLogs.push(args.map(String).join(' '));
    });
    vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      consoleErrors.push(args.map(String).join(' '));
    });

    const mockResult = makeScanResult();
    const mockScan = vi.fn().mockResolvedValue(mockResult);
    mockScanEngine.mockImplementation(function () { return { scan: mockScan } as any; });
    mockGetReporter.mockReturnValue({ format: 'terminal', render: () => 'rendered output' } as any);
  });

  afterEach(() => {
    process.exitCode = origExitCode;
  });

  it('renders scan output to console', async () => {
    await runScan({ format: 'terminal' });
    expect(consoleLogs.some(l => l.includes('rendered output'))).toBe(true);
  });

  it('saves baseline when flag set', async () => {
    mockSaveBaseline.mockResolvedValue('/tmp/baseline.json');
    await runScan({ format: 'terminal', saveBaseline: true });
    expect(mockSaveBaseline).toHaveBeenCalled();
    expect(consoleErrors.some(l => l.includes('Baseline saved'))).toBe(true);
  });

  it('diffs against baseline when flag set', async () => {
    const baseline = makeScanResult();
    mockLoadBaseline.mockResolvedValue(baseline);
    mockDiffResults.mockReturnValue({
      newFindings: [{ id: 'CFG-002', name: 'New', category: 'config' as const, severity: 'warning' as const, passed: false, message: 'new' }],
      resolvedFindings: [],
      unchangedFindings: [],
    });

    await runScan({ format: 'terminal', diff: true });
    expect(mockDiffResults).toHaveBeenCalled();
    expect(consoleErrors.some(l => l.includes('Differential'))).toBe(true);
  });

  it('does not compare with a pre-1.3.1 baseline that covers other agents', async () => {
    const legacy = makeScanResult();
    legacy.agents = legacy.agents.map(a => ({ ...a, agent: 'hermes' as const }));
    delete (legacy as { vasoVersion?: string }).vasoVersion;
    mockLoadBaseline.mockResolvedValue(legacy);
    mockDiffResults.mockClear();
    await runScan({ format: 'terminal', diff: true });
    expect(mockDiffResults).not.toHaveBeenCalled();
    expect(consoleErrors.some(l => l.includes("covers agents this scan doesn't (hermes)"))).toBe(true);
    expect(consoleErrors.some(l => l.includes('No baseline found'))).toBe(false);
  });

  it('compares the common agents with a pre-1.3.1 baseline that covers a subset of this scan', async () => {
    const current = makeScanResult();
    current.agents = [...current.agents, { ...current.agents[0], agent: 'grok-bot' as const, installation: { agent: 'grok-bot' as const, installDir: '/tmp/g', configFiles: [] } }];
    mockScanEngine.mockImplementation(function () { return { scan: vi.fn().mockResolvedValue(current) } as any; });
    const legacy = makeScanResult();
    delete (legacy as { vasoVersion?: string }).vasoVersion;
    mockLoadBaseline.mockResolvedValue(legacy);
    mockDiffResults.mockReturnValue({ newFindings: [], resolvedFindings: [], unchangedFindings: [] });
    await runScan({ format: 'terminal', diff: true });
    expect(mockDiffResults).toHaveBeenCalledTimes(1);
    expect(mockDiffResults.mock.calls[0][0].agents.map((a: { agent: string }) => a.agent)).toEqual(['openclaw']);
    expect(consoleErrors.some(l => l.includes('covers only openclaw') && l.includes('not in the baseline: grok-bot'))).toBe(true);
    expect(consoleErrors.some(l => l.includes('Differential'))).toBe(true);
  });

  it('warns about a damaged baseline and still writes the report', async () => {
    mockLoadBaseline.mockRejectedValue(new BaselineLoadError('/h/.vaso/baselines/latest.json is not valid JSON'));
    await runScan({ format: 'terminal', diff: true });
    expect(consoleLogs.some(l => l.includes('rendered output'))).toBe(true);
    expect(consoleErrors.some(l => l.includes("can't be used") && l.includes('not valid JSON'))).toBe(true);
    expect(consoleErrors.some(l => l.includes('No baseline found'))).toBe(false);
    expect(process.exitCode).not.toBe(2);
  });

  it('exits 2 when --save-baseline could not write, after writing the report', async () => {
    mockSaveBaseline.mockRejectedValue(new Error('EACCES: permission denied'));
    await runScan({ format: 'terminal', saveBaseline: true });
    expect(consoleLogs.some(l => l.includes('rendered output'))).toBe(true);
    expect(consoleErrors.some(l => l.includes('not saved') && l.includes('EACCES'))).toBe(true);
    expect(consoleErrors.some(l => l.includes('Baseline saved'))).toBe(false);
    expect(process.exitCode).toBe(2);
  });

  it('prints diff lines from a baseline escaped and masked', async () => {
    mockLoadBaseline.mockResolvedValue(makeScanResult());
    mockDiffResults.mockReturnValue({
      newFindings: [],
      resolvedFindings: [{ id: 'X\u001b[2J', name: 'n\u001b]0;t\u0007', category: 'config' as const, severity: 'warning' as const, passed: false, message: 'm' }],
      unchangedFindings: [],
    });
    await runScan({ format: 'terminal', diff: true });
    const line = consoleErrors.find(l => l.includes('[RESOLVED]'))!;
    expect(line).toContain('X\\x1b[2J');
    expect(line).not.toMatch(/\u001b\[2J|\u001b\]0/);
  });

  it('shows no baseline message when none found', async () => {
    mockLoadBaseline.mockResolvedValue(null);
    await runScan({ format: 'terminal', diff: true });
    expect(consoleErrors.some(l => l.includes('No baseline found'))).toBe(true);
  });

  it('writes to file when output option set', async () => {
    mockWriteFile.mockResolvedValue(undefined);
    await runScan({ format: 'json', output: '/tmp/report.json' });
    expect(mockWriteFile).toHaveBeenCalledWith('/tmp/report.json', 'rendered output', 'utf-8');
  });

  it('sets exit code 1 on critical findings', async () => {
    const critResult = makeScanResult({
      agents: [{
        agent: 'openclaw',
        installation: { agent: 'openclaw', installDir: '/tmp', configFiles: [] },
        results: [
          { id: 'CFG-001', name: 'Test', category: 'config', severity: 'critical', passed: false, message: 'crit' },
        ],
        score: 50,
        grade: 'D',
      }],
    });
    const mockScan = vi.fn().mockResolvedValue(critResult);
    mockScanEngine.mockImplementation(function () { return { scan: mockScan } as any; });

    await runScan({ format: 'terminal' });
    expect(process.exitCode).toBe(1);
  });

  it('sets exit code 2 when VASO itself fails (1 is reserved for findings)', async () => {
    const mockScan = vi.fn().mockRejectedValue(new Error('scan failed'));
    mockScanEngine.mockImplementation(function () { return { scan: mockScan } as any; });

    await runScan({ format: 'terminal' });
    expect(process.exitCode).toBe(2);
    expect(consoleErrors.some(l => l.includes('Scan failed'))).toBe(true);
  });

  it('passes agent filter to engine', async () => {
    const mockScan = vi.fn().mockResolvedValue(makeScanResult());
    mockScanEngine.mockImplementation(function () { return { scan: mockScan } as any; });

    await runScan({ format: 'terminal', agent: 'nanoclaw' });
    expect(mockScan).toHaveBeenCalledWith(expect.objectContaining({ agentFilter: 'nanoclaw' }));
  });

  it('uses correct reporter format', async () => {
    await runScan({ format: 'json' });
    expect(mockGetReporter).toHaveBeenCalledWith('json');
  });

  describe('--fail-on', () => {
    function setupResult(severity: 'critical' | 'warning' | 'info') {
      const r = makeScanResult({
        agents: [{
          agent: 'openclaw',
          installation: { agent: 'openclaw', installDir: '/tmp', configFiles: [] },
          results: [
            { id: 'X', name: 'x', category: 'config', severity, passed: false, message: 'fail' },
          ],
          score: 50,
          grade: 'D',
        }],
      });
      const mockScan = vi.fn().mockResolvedValue(r);
      mockScanEngine.mockImplementation(function () { return { scan: mockScan } as any; });
    }

    it('default (critical) does not trip on a warning-only result', async () => {
      setupResult('warning');
      await runScan({ format: 'terminal' });
      expect(process.exitCode).toBeUndefined();
    });

    it('--fail-on warning trips on a warning result', async () => {
      setupResult('warning');
      await runScan({ format: 'terminal', failOn: 'warning' });
      expect(process.exitCode).toBe(1);
    });

    it('--fail-on info trips on an info result', async () => {
      setupResult('info');
      await runScan({ format: 'terminal', failOn: 'info' });
      expect(process.exitCode).toBe(1);
    });

    it('--fail-on none does not trip even on critical', async () => {
      setupResult('critical');
      await runScan({ format: 'terminal', failOn: 'none' });
      expect(process.exitCode).toBeUndefined();
    });

    it('rejects an invalid --fail-on value with exit 2', async () => {
      await runScan({ format: 'terminal', failOn: 'fatal' });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('Invalid --fail-on'))).toBe(true);
    });
  });

  describe('multi-host option validation', () => {
    it('rejects non-numeric --parallel with exit 2', async () => {
      await runScan({
        format: 'terminal',
        host: ['root@10.0.0.1'],
        parallel: 'abc',
      });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('--parallel'))).toBe(true);
    });

    it('rejects --parallel=0 with exit 2', async () => {
      await runScan({
        format: 'terminal',
        host: ['root@10.0.0.1'],
        parallel: '0',
      });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('--parallel'))).toBe(true);
    });

    it('rejects negative --ssh-retries with exit 2', async () => {
      await runScan({
        format: 'terminal',
        host: ['root@10.0.0.1'],
        sshRetries: '-1',
      });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('--ssh-retries'))).toBe(true);
    });

    it.each(['abc', '0', '5s', '-3'])('rejects --ssh-timeout %s with exit 2 before connecting', async (sshTimeout) => {
      await runScan({ format: 'terminal', host: ['root@10.0.0.1'], sshTimeout });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('--ssh-timeout'))).toBe(true);
    });

    it('rejects --parallel with trailing garbage (2x) with exit 2', async () => {
      await runScan({ format: 'terminal', host: ['root@10.0.0.1'], parallel: '2x' });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('--parallel'))).toBe(true);
    });

    it('rejects -o + --output-dir together with exit 2', async () => {
      await runScan({
        format: 'terminal',
        host: ['root@10.0.0.1'],
        output: '/tmp/report.txt',
        outputDir: '/tmp/reports/',
      });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('mutually exclusive'))).toBe(true);
    });

    it('rejects --save-snapshot on a local scan with exit 2', async () => {
      await runScan({ format: 'terminal', saveSnapshot: '/tmp/snaps' });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('--save-snapshot applies to remote scans only'))).toBe(true);
    });

    it('rejects --silent without -o or --output-dir for multi-host with exit 2', async () => {
      await runScan({
        format: 'terminal',
        host: ['root@10.0.0.1'],
        silent: true,
      });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('--silent requires'))).toBe(true);
    });

    it('rejects -o file.sarif for multi-host (cannot aggregate SARIF)', async () => {
      await runScan({
        format: 'sarif',
        host: ['root@10.0.0.1', 'root@10.0.0.2'],
        output: '/tmp/results.sarif',
      });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('--output-dir'))).toBe(true);
    });

    it('rejects -o file.xml for multi-host JUnit (cannot aggregate)', async () => {
      await runScan({
        format: 'junit',
        host: ['root@10.0.0.1', 'root@10.0.0.2'],
        output: '/tmp/results.xml',
      });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('--output-dir'))).toBe(true);
    });
  });

  describe('local --silent', () => {
    it('rejects --silent without -o for local scans with exit 2', async () => {
      await runScan({ format: 'terminal', silent: true });
      expect(process.exitCode).toBe(2);
      expect(consoleErrors.some(l => l.includes('--silent requires'))).toBe(true);
    });

    it('--silent + -o suppresses the "Report written to" message', async () => {
      mockWriteFile.mockResolvedValue(undefined);
      await runScan({ format: 'json', output: '/tmp/r.json', silent: true });
      expect(mockWriteFile).toHaveBeenCalledWith('/tmp/r.json', 'rendered output', 'utf-8');
      expect(consoleLogs.some(l => l.includes('Report written'))).toBe(false);
    });
  });

  describe('-o auto-creates parent directory', () => {
    it('mkdir -p the parent of -o before writing', async () => {
      mockWriteFile.mockResolvedValue(undefined);
      mockMkdir.mockResolvedValue(undefined as never);

      await runScan({ format: 'json', output: '/tmp/reports/run-1/report.json' });

      expect(mockMkdir).toHaveBeenCalledWith('/tmp/reports/run-1', { recursive: true });
      expect(mockWriteFile).toHaveBeenCalledWith('/tmp/reports/run-1/report.json', 'rendered output', 'utf-8');
    });
  });
});
