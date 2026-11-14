import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../core/engine.js', () => ({
  ScanEngine: vi.fn(),
}));

vi.mock('../remediation/engine.js', async (orig) => ({
  ...(await orig<typeof import('../remediation/engine.js')>()),
  RemediationEngine: vi.fn(),
}));

vi.mock('../remediation/rollback.js', () => ({
  rollback: vi.fn(),
}));

import { ScanEngine } from '../core/engine.js';
import { RemediationEngine } from '../remediation/engine.js';
import { rollback } from '../remediation/rollback.js';
import { runFix } from './fix.js';

const mockScanEngine = vi.mocked(ScanEngine);
const mockRemediationEngine = vi.mocked(RemediationEngine);
const mockRollback = vi.mocked(rollback);

describe('runFix', () => {
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
  });

  afterEach(() => {
    process.exitCode = origExitCode;
  });

  it('delegates to rollback when rollback flag set', async () => {
    mockRollback.mockResolvedValue(undefined);
    await runFix({ rollback: true });
    expect(mockRollback).toHaveBeenCalled();
  });

  it('never runs fixes for an empty --rollback value', async () => {
    await runFix({ rollback: '' });
    expect(mockRollback).not.toHaveBeenCalled();
    expect(mockScanEngine).not.toHaveBeenCalled();
    expect(process.exitCode).toBe(2);
    process.exitCode = undefined;
  });

  it('shows message when no agents detected', async () => {
    const mockScan = vi.fn().mockResolvedValue({ agents: [] });
    mockScanEngine.mockImplementation(function () { return { scan: mockScan } as any; });

    await runFix({ yes: true });
    expect(consoleLogs.some(l => l.includes('No agents detected'))).toBe(true);
  });

  it('shows message when no fixable issues', async () => {
    const mockScan = vi.fn().mockResolvedValue({
      agents: [{
        agent: 'openclaw',
        results: [{ id: 'CFG-001', passed: false, fixable: false }],
      }],
    });
    mockScanEngine.mockImplementation(function () { return { scan: mockScan } as any; });

    await runFix({ yes: true });
    expect(consoleLogs.some(l => l.includes('No fixable issues'))).toBe(true);
  });

  it('passes dry-run and yes options to remediation engine', async () => {
    const mockScan = vi.fn().mockResolvedValue({
      agents: [{
        agent: 'openclaw',
        results: [{ id: 'CFG-001', passed: false, fixable: true }],
      }],
    });
    mockScanEngine.mockImplementation(function () { return { scan: mockScan } as any; });

    const mockFix = vi.fn().mockResolvedValue([{ applied: true }]);
    mockRemediationEngine.mockImplementation(function () { return { fix: mockFix, stillOpen: () => [] } as any; });

    await runFix({ dryRun: true, yes: true });
    expect(mockFix).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ dryRun: true, yes: true }),
    );
  });

  it('runs fixes for folded findings (passing, fixable, foldedInto) — they are the only chmod fix', async () => {
    const mockScan = vi.fn().mockResolvedValue({
      agents: [{
        agent: 'gemini-cli',
        results: [
          { id: 'GEM-002', passed: false },
          { id: 'POL-003', passed: true, fixable: true, foldedInto: 'GEM-002' },
        ],
      }],
    });
    mockScanEngine.mockImplementation(function () { return { scan: mockScan } as any; });
    const mockFix = vi.fn().mockResolvedValue([{ applied: true }]);
    mockRemediationEngine.mockImplementation(function () { return { fix: mockFix, stillOpen: () => [] } as any; });

    await runFix({ yes: true });
    expect(mockFix).toHaveBeenCalled();
    expect(consoleLogs.some(l => l.includes('No fixable issues'))).toBe(false);
  });

  it('reports applied fix count', async () => {
    const mockScan = vi.fn().mockResolvedValue({
      agents: [{
        agent: 'openclaw',
        results: [
          { id: 'CFG-001', passed: false, fixable: true },
          { id: 'CFG-002', passed: false, fixable: true },
        ],
      }],
    });
    mockScanEngine.mockImplementation(function () { return { scan: mockScan } as any; });

    const mockFix = vi.fn().mockResolvedValue([
      { applied: true },
      { applied: false },
    ]);
    mockRemediationEngine.mockImplementation(function () { return { fix: mockFix, stillOpen: () => [] } as any; });

    await runFix({ yes: true });
    expect(consoleLogs.some(l => l.includes('1 applied, 1 not applied'))).toBe(true);
    // an unapplied fix leaves its finding open
    expect(process.exitCode).toBe(1);
    process.exitCode = undefined;
  });

  it('sets exit code 1 on error', async () => {
    const mockScan = vi.fn().mockRejectedValue(new Error('fix failed'));
    mockScanEngine.mockImplementation(function () { return { scan: mockScan } as any; });

    await runFix({ yes: true });
    expect(process.exitCode).toBe(1);
    expect(consoleErrors.some(l => l.includes('Fix failed'))).toBe(true);
  });

  it('names applied fixes whose finding is still reported after a rescan', async () => {
    const scanResult = { agents: [{ agent: 'zeroclaw', results: [{ id: 'ZC-008', passed: false, fixable: true }] }] };
    const mockScan = vi.fn().mockResolvedValue(scanResult);
    mockScanEngine.mockImplementation(function () { return { scan: mockScan } as any; });
    const mockFix = vi.fn().mockResolvedValue([{ checkId: 'ZC-008', applied: true }]);
    const stillOpen = vi.fn().mockReturnValue([{ checkId: 'ZC-008', result: { applied: true }, finding: { id: 'ZC-008', severity: 'warning', message: 'open skills still on' } }]);
    mockRemediationEngine.mockImplementation(function () { return { fix: mockFix, stillOpen } as any; });

    await runFix({ yes: true });
    expect(mockScan).toHaveBeenCalledTimes(2);
    expect(stillOpen).toHaveBeenCalledWith(scanResult);
    expect(consoleLogs.some(l => l.includes('ZC-008 (warning): open skills still on'))).toBe(true);
    expect(consoleLogs.some(l => l.includes('1 applied (1 partially — finding still open)'))).toBe(true);
  });

  it('exits 2 without --yes on a non-interactive terminal, before scanning', async () => {
    const tty = process.stdin.isTTY;
    Object.defineProperty(process.stdin, 'isTTY', { value: false, configurable: true });
    try {
      await runFix({});
      expect(process.exitCode).toBe(2);
      expect(mockScanEngine).not.toHaveBeenCalled();
      expect(consoleErrors.some(l => l.includes('--yes'))).toBe(true);
    } finally {
      Object.defineProperty(process.stdin, 'isTTY', { value: tty, configurable: true });
      process.exitCode = undefined;
    }
  });

  it('passes agent filter to scan', async () => {
    const mockScan = vi.fn().mockResolvedValue({ agents: [] });
    mockScanEngine.mockImplementation(function () { return { scan: mockScan } as any; });

    await runFix({ agent: 'nanoclaw', yes: true });
    expect(mockScan).toHaveBeenCalledWith(expect.objectContaining({ agentFilter: 'nanoclaw' }));
  });
});
