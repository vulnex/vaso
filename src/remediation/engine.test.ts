import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import type { ScanResult, CheckResult, FixResult, CheckModule, ScanContext } from '../core/types.js';
import { RemediationEngine } from './engine.js';
import { CheckRegistry } from '../core/check-registry.js';
import { AdapterRegistry } from '../adapters/registry.js';
import type { AgentAdapter } from '../adapters/adapter.js';

// Mock prompt module
const mockPromptForFix = vi.fn();
vi.mock('./prompt.js', () => ({
  promptForFix: (...args: unknown[]) => mockPromptForFix(...args),
}));

function makeFixableCheck(id: string, applies = true): CheckModule {
  return {
    id,
    name: `Check ${id}`,
    category: 'config',
    severity: 'warning',
    description: `Test check ${id}`,
    run: vi.fn().mockResolvedValue({
      id,
      name: `Check ${id}`,
      category: 'config',
      severity: 'warning',
      passed: false,
      message: `Issue ${id}`,
      fixable: true,
      fixDescription: `Fix ${id}`,
    } satisfies CheckResult),
    fix: vi.fn().mockResolvedValue({
      checkId: id,
      applied: true,
      message: `Fixed ${id}`,
    } satisfies FixResult),
  };
}

function makeScanResult(...checkIds: string[]): ScanResult {
  const results: CheckResult[] = checkIds.map(id => ({
    id,
    name: `Check ${id}`,
    category: 'config' as const,
    severity: 'warning' as const,
    passed: false,
    message: `Issue ${id}`,
    fixable: true,
    fixDescription: `Fix ${id}`,
  }));

  return {
    timestamp: '2026-01-01T00:00:00.000Z',
    agents: [{
      agent: 'openclaw',
      installation: { agent: 'openclaw', installDir: '/tmp', configFiles: [] },
      results,
      score: 50,
      grade: 'D',
    }],
    totalScore: 50,
    totalGrade: 'D',
    fleetAverage: 50,
    summary: { critical: 0, warning: checkIds.length, info: 0, passed: 0, total: checkIds.length },
  };
}

function makeScanResultWithEvidence(checkId: string, file: string): ScanResult {
  const result = makeScanResult(checkId);
  result.agents[0].results[0].evidence = [{ file }];
  return result;
}

let consoleLogs: string[];
const originalLog = console.log;
const originalIsTTY = process.stdin.isTTY;

beforeEach(() => {
  consoleLogs = [];
  console.log = (...args: unknown[]) => {
    consoleLogs.push(args.map(String).join(' '));
  };
  // Simulate TTY for interactive tests
  Object.defineProperty(process.stdin, 'isTTY', { value: true, writable: true, configurable: true });
  vi.clearAllMocks();
});

afterEach(() => {
  console.log = originalLog;
  Object.defineProperty(process.stdin, 'isTTY', { value: originalIsTTY, writable: true, configurable: true });
});

describe('RemediationEngine interactive fix', () => {
  it('applies all fixes without prompts when options.yes=true', async () => {
    const check = makeFixableCheck('TST-001');
    const registry = new CheckRegistry();
    registry.register(check);
    const engine = new RemediationEngine(registry);

    const results = await engine.fix(makeScanResult('TST-001'), { yes: true });

    expect(mockPromptForFix).not.toHaveBeenCalled();
    expect(results).toHaveLength(1);
    expect(results[0].applied).toBe(true);
  });

  it('does not apply fixes and does not prompt in dry-run mode', async () => {
    const check = makeFixableCheck('TST-001');
    const registry = new CheckRegistry();
    registry.register(check);
    const engine = new RemediationEngine(registry);

    const results = await engine.fix(makeScanResult('TST-001'), { dryRun: true });

    expect(mockPromptForFix).not.toHaveBeenCalled();
    expect(results).toHaveLength(1);
    expect(results[0].applied).toBe(false);
    expect(results[0].message).toContain('Dry run');
  });

  it('prompts and applies fix when user answers "yes"', async () => {
    mockPromptForFix.mockResolvedValue('yes');
    const check = makeFixableCheck('TST-001');
    const registry = new CheckRegistry();
    registry.register(check);
    const engine = new RemediationEngine(registry);

    const results = await engine.fix(makeScanResult('TST-001'), {});

    expect(mockPromptForFix).toHaveBeenCalledTimes(1);
    expect(results).toHaveLength(1);
    expect(results[0].applied).toBe(true);
  });

  it('skips fix when user answers "no"', async () => {
    mockPromptForFix.mockResolvedValue('no');
    const check = makeFixableCheck('TST-001');
    const registry = new CheckRegistry();
    registry.register(check);
    const engine = new RemediationEngine(registry);

    const results = await engine.fix(makeScanResult('TST-001'), {});

    expect(mockPromptForFix).toHaveBeenCalledTimes(1);
    expect(results).toHaveLength(1);
    expect(results[0].applied).toBe(false);
    expect(results[0].message).toBe('Skipped by user');
  });

  it('skips remaining fixes and returns early on "quit"', async () => {
    mockPromptForFix.mockResolvedValueOnce('yes').mockResolvedValueOnce('quit');

    const check1 = makeFixableCheck('TST-001');
    const check2 = makeFixableCheck('TST-002');
    const check3 = makeFixableCheck('TST-003');
    const registry = new CheckRegistry();
    registry.register(check1);
    registry.register(check2);
    registry.register(check3);
    const engine = new RemediationEngine(registry);

    const results = await engine.fix(makeScanResult('TST-001', 'TST-002', 'TST-003'), {});

    // First prompted -> yes -> applied
    // Second prompted -> quit -> skipped, early return
    // Third never reached
    expect(mockPromptForFix).toHaveBeenCalledTimes(2);
    expect(results).toHaveLength(2);
    expect(results[0].applied).toBe(true);
    expect(results[1].applied).toBe(false);
    expect(results[1].message).toBe('Skipped by user');
  });

  it('stops prompting after "all" and applies remaining fixes', async () => {
    mockPromptForFix.mockResolvedValueOnce('no').mockResolvedValueOnce('all');

    const check1 = makeFixableCheck('TST-001');
    const check2 = makeFixableCheck('TST-002');
    const check3 = makeFixableCheck('TST-003');
    const registry = new CheckRegistry();
    registry.register(check1);
    registry.register(check2);
    registry.register(check3);
    const engine = new RemediationEngine(registry);

    const results = await engine.fix(makeScanResult('TST-001', 'TST-002', 'TST-003'), {});

    // First prompted -> no -> skipped
    // Second prompted -> all -> applied, no more prompts
    // Third auto-applied (no prompt)
    expect(mockPromptForFix).toHaveBeenCalledTimes(2);
    expect(results).toHaveLength(3);
    expect(results[0].applied).toBe(false);
    expect(results[1].applied).toBe(true);
    expect(results[2].applied).toBe(true);
  });

  it('handles fix failure in interactive mode gracefully', async () => {
    mockPromptForFix.mockResolvedValue('yes');

    const check = makeFixableCheck('TST-001');
    (check.fix as ReturnType<typeof vi.fn>).mockRejectedValue(new Error('Permission denied'));
    const registry = new CheckRegistry();
    registry.register(check);
    const engine = new RemediationEngine(registry);

    const results = await engine.fix(makeScanResult('TST-001'), {});

    expect(results).toHaveLength(1);
    expect(results[0].applied).toBe(false);
    expect(results[0].message).toContain('Fix failed');
    expect(results[0].message).toContain('Permission denied');
  });

  it('does not apply a fix when backing up evidence fails', async () => {
    const check = makeFixableCheck('TST-001');
    const registry = new CheckRegistry();
    registry.register(check);
    const engine = new RemediationEngine(registry);

    const results = await engine.fix(makeScanResultWithEvidence('TST-001', '/definitely/not/present'), { yes: true });

    expect(check.fix).not.toHaveBeenCalled();
    expect(results).toHaveLength(1);
    expect(results[0].applied).toBe(false);
    expect(results[0].message).toContain('Fix failed');
  });

  it('warns and skips in non-TTY environment without --yes', async () => {
    Object.defineProperty(process.stdin, 'isTTY', { value: false, writable: true, configurable: true });

    const check = makeFixableCheck('TST-001');
    const registry = new CheckRegistry();
    registry.register(check);
    const engine = new RemediationEngine(registry);

    const results = await engine.fix(makeScanResult('TST-001'), {});

    expect(results).toHaveLength(0);
    expect(consoleLogs.join('\n')).toContain('Non-interactive terminal');
    expect(mockPromptForFix).not.toHaveBeenCalled();
  });

  it('applies fixes in non-TTY when --yes is set', async () => {
    Object.defineProperty(process.stdin, 'isTTY', { value: false, writable: true, configurable: true });

    const check = makeFixableCheck('TST-001');
    const registry = new CheckRegistry();
    registry.register(check);
    const engine = new RemediationEngine(registry);

    const results = await engine.fix(makeScanResult('TST-001'), { yes: true });

    expect(results).toHaveLength(1);
    expect(results[0].applied).toBe(true);
    expect(mockPromptForFix).not.toHaveBeenCalled();
  });

  it('passes adapter-derived credentialPaths through to check.fix()', async () => {
    // Regression: without this, fixes like CFG-003 (chmod credential files)
    // silently no-op because their fix() runs against an empty
    // ctx.credentialPaths and finds no files to remediate.
    let capturedCtx: ScanContext | undefined;
    const check: CheckModule = {
      id: 'TST-CRED',
      name: 'Test Credential Check',
      category: 'config',
      severity: 'warning',
      description: 'test',
      run: vi.fn(),
      fix: vi.fn(async (ctx) => {
        capturedCtx = ctx;
        return { checkId: 'TST-CRED', applied: true, message: 'ok' } satisfies FixResult;
      }),
    };

    const fakeAdapter: AgentAdapter = {
      agent: 'openclaw',
      displayName: 'Test',
      async detect() { return []; },
      getConfigPaths() { return []; },
      getSkillsDir() { return undefined; },
      getGatewayInfo() { return undefined; },
      getCredentialPaths(installDir: string) { return [`${installDir}/auth.json`]; },
      getProbeManifest() { return { filePaths: [], globPatterns: [], commands: [], directoryListings: [], envPrefixes: [], systemPaths: [], systemDirListings: [] }; },
    };

    const adapters = new AdapterRegistry();
    adapters.register(fakeAdapter);
    const registry = new CheckRegistry();
    registry.register(check);
    const engine = new RemediationEngine(registry, adapters);

    const scanResult = makeScanResult('TST-CRED');
    scanResult.agents[0].installation.installDir = '/some/install';
    await engine.fix(scanResult, { yes: true });

    expect(capturedCtx?.credentialPaths).toEqual(['/some/install/auth.json']);
  });
});
