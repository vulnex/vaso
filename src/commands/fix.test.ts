import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

vi.mock('../core/engine.js', () => ({
  ScanEngine: vi.fn(),
}));

vi.mock('../remediation/engine.js', () => ({
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

  it('shows message when no agents detected', async () => {
    const mockScan = vi.fn().mockResolvedValue({ agents: [] });
    mockScanEngine.mockImplementation(() => ({ scan: mockScan } as any));

    await runFix({});
    expect(consoleLogs.some(l => l.includes('No agents detected'))).toBe(true);
  });

  it('shows message when no fixable issues', async () => {
    const mockScan = vi.fn().mockResolvedValue({
      agents: [{
        agent: 'openclaw',
        results: [{ id: 'CFG-001', passed: false, fixable: false }],
      }],
    });
    mockScanEngine.mockImplementation(() => ({ scan: mockScan } as any));

    await runFix({});
    expect(consoleLogs.some(l => l.includes('No fixable issues'))).toBe(true);
  });

  it('passes dry-run and yes options to remediation engine', async () => {
    const mockScan = vi.fn().mockResolvedValue({
      agents: [{
        agent: 'openclaw',
        results: [{ id: 'CFG-001', passed: false, fixable: true }],
      }],
    });
    mockScanEngine.mockImplementation(() => ({ scan: mockScan } as any));

    const mockFix = vi.fn().mockResolvedValue([{ applied: true }]);
    mockRemediationEngine.mockImplementation(() => ({ fix: mockFix } as any));

    await runFix({ dryRun: true, yes: true });
    expect(mockFix).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ dryRun: true, yes: true }),
    );
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
    mockScanEngine.mockImplementation(() => ({ scan: mockScan } as any));

    const mockFix = vi.fn().mockResolvedValue([
      { applied: true },
      { applied: false },
    ]);
    mockRemediationEngine.mockImplementation(() => ({ fix: mockFix } as any));

    await runFix({});
    expect(consoleLogs.some(l => l.includes('1/2 fixes applied'))).toBe(true);
  });

  it('sets exit code 1 on error', async () => {
    const mockScan = vi.fn().mockRejectedValue(new Error('fix failed'));
    mockScanEngine.mockImplementation(() => ({ scan: mockScan } as any));

    await runFix({});
    expect(process.exitCode).toBe(1);
    expect(consoleErrors.some(l => l.includes('Fix failed'))).toBe(true);
  });

  it('passes agent filter to scan', async () => {
    const mockScan = vi.fn().mockResolvedValue({ agents: [] });
    mockScanEngine.mockImplementation(() => ({ scan: mockScan } as any));

    await runFix({ agent: 'nanoclaw' });
    expect(mockScan).toHaveBeenCalledWith(expect.objectContaining({ agentFilter: 'nanoclaw' }));
  });
});
