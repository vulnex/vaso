import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const home = { dir: '' };
vi.mock('node:os', async (orig) => ({ ...(await orig<typeof import('node:os')>()), homedir: () => home.dir }));

import { RemediationEngine } from './engine.js';
import { CheckRegistry } from '../core/check-registry.js';
import { defineCheck } from '../core/check-builder.js';
import type { ScanResult, CheckResult } from '../core/types.js';

function scanWith(results: CheckResult[], installDir: string): ScanResult {
  return {
    timestamp: 't', totalScore: 0, totalGrade: 'F', fleetAverage: 0,
    summary: { critical: 0, warning: 1, info: 0, passed: 0, total: 1 },
    agents: [{ agent: 'zeroclaw', installation: { agent: 'zeroclaw', installDir, configFiles: [] }, results, score: 0, grade: 'F' }],
  };
}

describe('RemediationEngine.stillOpen', () => {
  beforeEach(async () => {
    home.dir = await mkdtemp(join(tmpdir(), 'vaso-open-'));
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
  });
  afterEach(async () => {
    vi.restoreAllMocks();
    await rm(home.dir, { recursive: true, force: true });
  });

  it('names an applied fix whose finding the rescan still reports on the same installation', async () => {
    const registry = new CheckRegistry();
    for (const id of ['TST-001', 'TST-002']) {
      registry.register(defineCheck({
        id, name: id, category: 'config', severity: 'warning', description: id,
        async run(_c, h) { return h.passed('x'); },
        async fix() { return { checkId: id, applied: true, message: 'changed' }; },
      }));
    }
    const failing = (id: string): CheckResult => ({ id, name: id, category: 'config', severity: 'warning', passed: false, message: `${id} open`, fixable: true });
    const engine = new RemediationEngine(registry);
    await engine.fix(scanWith([failing('TST-001'), failing('TST-002')], home.dir), { yes: true });

    const open = engine.stillOpen(scanWith([failing('TST-001'), { ...failing('TST-002'), passed: true }], home.dir));
    expect(open.map(o => [o.checkId, o.finding.message])).toEqual([['TST-001', 'TST-001 open']]);
    // another installation's finding is not this fix's
    expect(engine.stillOpen(scanWith([failing('TST-001')], join(home.dir, 'other')))).toEqual([]);
  });
});
