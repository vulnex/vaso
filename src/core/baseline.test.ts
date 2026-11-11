import { describe, it, expect } from 'vitest';
import { diffResults } from './baseline.js';
import type { ScanResult, CheckResult, AgentScanResult } from './types.js';

function makeCheckResult(id: string, passed: boolean, severity: 'critical' | 'warning' | 'info' = 'warning'): CheckResult {
  return {
    id,
    name: `Check ${id}`,
    category: 'config',
    severity,
    passed,
    message: passed ? 'OK' : 'Failed',
  };
}

function makeScanResult(checks: CheckResult[], installDir = '/tmp'): ScanResult {
  const agent: AgentScanResult = {
    agent: 'openclaw',
    installation: { agent: 'openclaw', installDir, configFiles: [] },
    results: checks,
    score: 100,
    grade: 'A',
  };
  return {
    timestamp: new Date().toISOString(),
    agents: [agent],
    totalScore: 100,
    totalGrade: 'A',
    fleetAverage: 100,
    summary: { critical: 0, warning: 0, info: 0, passed: 0, total: checks.length },
  };
}

describe('diffResults', () => {
  it('detects new findings', () => {
    const baseline = makeScanResult([makeCheckResult('CFG-001', false)]);
    const current = makeScanResult([
      makeCheckResult('CFG-001', false),
      makeCheckResult('CFG-002', false),
    ]);
    const diff = diffResults(current, baseline);
    console.log(`[diffResults] new findings → new: ${diff.newFindings.map(f => f.id)}, unchanged: ${diff.unchangedFindings.map(f => f.id)}, resolved: ${diff.resolvedFindings.map(f => f.id)}`);
    expect(diff.newFindings).toHaveLength(1);
    expect(diff.newFindings[0].id).toBe('CFG-002');
    expect(diff.unchangedFindings).toHaveLength(1);
    expect(diff.resolvedFindings).toHaveLength(0);
  });

  it('detects resolved findings', () => {
    const baseline = makeScanResult([
      makeCheckResult('CFG-001', false),
      makeCheckResult('CFG-002', false),
    ]);
    const current = makeScanResult([makeCheckResult('CFG-001', false)]);
    const diff = diffResults(current, baseline);
    console.log(`[diffResults] resolved findings → new: ${diff.newFindings.map(f => f.id)}, unchanged: ${diff.unchangedFindings.map(f => f.id)}, resolved: ${diff.resolvedFindings.map(f => f.id)}`);
    expect(diff.resolvedFindings).toHaveLength(1);
    expect(diff.resolvedFindings[0].id).toBe('CFG-002');
  });

  it('handles identical results', () => {
    const baseline = makeScanResult([makeCheckResult('CFG-001', false)]);
    const current = makeScanResult([makeCheckResult('CFG-001', false)]);
    const diff = diffResults(current, baseline);
    console.log(`[diffResults] identical → new: ${diff.newFindings.length}, unchanged: ${diff.unchangedFindings.length}, resolved: ${diff.resolvedFindings.length}`);
    expect(diff.newFindings).toHaveLength(0);
    expect(diff.resolvedFindings).toHaveLength(0);
    expect(diff.unchangedFindings).toHaveLength(1);
  });

  it('ignores passed checks', () => {
    const baseline = makeScanResult([makeCheckResult('CFG-001', true)]);
    const current = makeScanResult([makeCheckResult('CFG-001', true)]);
    const diff = diffResults(current, baseline);
    console.log(`[diffResults] all passed → new: ${diff.newFindings.length}, unchanged: ${diff.unchangedFindings.length}, resolved: ${diff.resolvedFindings.length}`);
    expect(diff.newFindings).toHaveLength(0);
    expect(diff.resolvedFindings).toHaveLength(0);
    expect(diff.unchangedFindings).toHaveLength(0);
  });

  it('does not collapse same check across different installations', () => {
    const baseline = makeScanResult([makeCheckResult('CFG-001', false)], '/tmp/a');
    const current: ScanResult = {
      ...baseline,
      agents: [
        baseline.agents[0],
        makeScanResult([makeCheckResult('CFG-001', false)], '/tmp/b').agents[0],
      ],
    };

    const diff = diffResults(current, baseline);
    expect(diff.unchangedFindings).toHaveLength(1);
    expect(diff.newFindings).toHaveLength(1);
    expect(diff.newFindings[0].id).toBe('CFG-001');
  });
});

describe('diffResults keys', () => {
  it('treats a finding whose wording or line moved as unchanged', () => {
    const before = makeCheckResult('CFG-001', false);
    before.evidence = [{ file: '/a/config.json', line: 3, detail: 'old wording' }];
    const after = makeCheckResult('CFG-001', false);
    after.evidence = [{ file: '/a/config.json', line: 9, detail: 'new wording' }];
    const diff = diffResults(makeScanResult([after]), makeScanResult([before]));
    expect(diff.unchangedFindings).toHaveLength(1);
    expect(diff.newFindings).toHaveLength(0);
    expect(diff.resolvedFindings).toHaveLength(0);
  });

  it('still reports a finding in a new file as new', () => {
    const before = makeCheckResult('CFG-001', false);
    before.evidence = [{ file: '/a/config.json' }];
    const after = makeCheckResult('CFG-001', false);
    after.evidence = [{ file: '/a/other.json' }];
    const diff = diffResults(makeScanResult([after]), makeScanResult([before]));
    expect(diff.newFindings).toHaveLength(1);
    expect(diff.resolvedFindings).toHaveLength(1);
  });
});

describe('dt21 g8-F22 / g8-R5: a finding that gains or loses a file', () => {
  const at = (...files: string[]) => Object.assign(makeCheckResult('CC-004', false), { evidence: files.map(file => ({ file })) });

  it('stays unchanged when it loses a file but still names one of the same', () => {
    const lost = diffResults(makeScanResult([at('/h/.claude/settings.json')]), makeScanResult([at('/h/.claude/settings.json', '/h/.claude/settings.local.json')]));
    expect(lost).toMatchObject({ newFindings: [], resolvedFindings: [] });
    expect(lost.unchangedFindings).toHaveLength(1);
  });

  it('is new (not also resolved) when it names a file the baseline did not — a secret leaked into a new file', () => {
    const gained = diffResults(makeScanResult([at('/h/.claude/settings.json', '/h/.claude/settings.local.json')]), makeScanResult([at('/h/.claude/settings.json')]));
    expect(gained.newFindings).toHaveLength(1);
    expect(gained.resolvedFindings).toHaveLength(0);
    expect(gained.unchangedFindings).toHaveLength(0);
  });

  it('keeps repeated ids (one CONFIG-LOAD per file) apart by file', () => {
    const load = (file: string) => Object.assign(makeCheckResult('CONFIG-LOAD', false), { evidence: [{ file }] });
    const diff = diffResults(makeScanResult([load('/a.json'), load('/b.json')]), makeScanResult([load('/a.json')]));
    expect(diff.newFindings.map(f => f.evidence?.[0].file)).toEqual(['/b.json']);
    expect(diff.unchangedFindings).toHaveLength(1);
    expect(diff.resolvedFindings).toHaveLength(0);
  });
});

describe('baseline scopes', () => {
  it('keeps a separate latest baseline per agent filter and host', async () => {
    const { mkdtemp, rm, readdir } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const home = await mkdtemp(join(tmpdir(), 'vaso-bl-'));
    const { vi } = await import('vitest');
    vi.resetModules();
    vi.doMock('node:os', async (orig) => ({ ...(await orig<typeof import('node:os')>()), homedir: () => home }));
    try {
      const { saveBaseline, loadBaseline } = await import('./baseline.js');
      const hermes = makeScanResult([makeCheckResult('HM-001', false)]);
      await saveBaseline(hermes, { agent: 'hermes' });
      await saveBaseline(makeScanResult([]), {});
      expect((await loadBaseline({ agent: 'hermes' }))?.agents[0].results[0].id).toBe('HM-001');
      expect(await loadBaseline({ agent: 'abacus' })).toBeNull();
      expect((await readdir(join(home, '.vaso', 'baselines'))).filter(f => f.startsWith('latest')).sort())
        .toEqual(['latest-hermes.json', 'latest.json']);
    } finally {
      vi.doUnmock('node:os');
      vi.resetModules();
      await rm(home, { recursive: true, force: true });
    }
  });

  it('falls back to a pre-1.3.1 latest.json that covers exactly the scope', async () => {
    const { mkdtemp, rm, mkdir, writeFile } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const home = await mkdtemp(join(tmpdir(), 'vaso-bl-'));
    const { vi } = await import('vitest');
    vi.resetModules();
    vi.doMock('node:os', async (orig) => ({ ...(await orig<typeof import('node:os')>()), homedir: () => home }));
    try {
      const { loadBaseline } = await import('./baseline.js');
      const dir = join(home, '.vaso', 'baselines');
      await mkdir(dir, { recursive: true });
      // 1.3.0: `-a openclaw --save-baseline` wrote latest.json, no vasoVersion
      await writeFile(join(dir, 'latest.json'), JSON.stringify(makeScanResult([makeCheckResult('CFG-001', false)])));
      expect((await loadBaseline({ agent: 'openclaw' }))?.agents[0].results[0].id).toBe('CFG-001');
      expect(await loadBaseline({ agent: 'hermes' })).toBeNull();
      expect(await loadBaseline({ agent: 'openclaw', host: 'box' })).toBeNull();
      // a 1.3.1 baseline in latest.json is the unscoped one, never reused for a scope
      await writeFile(join(dir, 'latest.json'), JSON.stringify({ ...makeScanResult([]), vasoVersion: '1.3.1' }));
      expect(await loadBaseline({ agent: 'openclaw' })).toBeNull();
    } finally {
      vi.doUnmock('node:os');
      vi.resetModules();
      await rm(home, { recursive: true, force: true });
    }
  });
});
