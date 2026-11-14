import { describe, it, expect, vi, beforeEach } from 'vitest';

const scanMultipleHosts = vi.fn(async () => []);
vi.mock('../transport/multi-host.js', () => ({ scanMultipleHosts }));

import { runScan } from './scan.js';

describe('remote scan options', () => {
  beforeEach(() => {
    scanMultipleHosts.mockClear();
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  it('passes --all-users (and the agent filter) to every host scan', async () => {
    await runScan({ format: 'json', host: ['root@10.0.0.1'], allUsers: true, agent: 'zeroclaw' });
    expect(scanMultipleHosts).toHaveBeenCalledTimes(1);
    const args = scanMultipleHosts.mock.calls[0][0] as { scanOptions: Record<string, unknown> };
    expect(args.scanOptions).toMatchObject({ allUsers: true, agentFilter: 'zeroclaw' });
  });

  it('keeps one baseline per --host target, even when two hosts report the same hostname', async () => {
    const { readdir } = await import('node:fs/promises');
    const { join } = await import('node:path');
    const { homedir } = await import('node:os');
    const result = (n: number) => ({
      timestamp: 't', vasoVersion: '1.3.1', host: 'web', totalScore: 100, totalGrade: 'A', fleetAverage: 100,
      summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 },
      agents: [{ agent: 'openclaw', installation: { agent: 'openclaw', installDir: `/srv/${n}`, configFiles: [] }, results: [], score: 100, grade: 'A' }],
    });
    scanMultipleHosts.mockImplementationOnce((async (opts: { targets: Array<{ user?: string; host: string }>; onComplete?: (e: unknown) => Promise<void> }) => {
      const entries = opts.targets.map((target, i) => ({ target, durationMs: 1, result: result(i) }));
      for (const e of entries) await opts.onComplete?.(e);
      return entries;
    }) as never);
    await runScan({ format: 'json', host: ['ops@10.0.0.1', 'ops@10.0.0.2'], saveBaseline: true });
    const files = (await readdir(join(homedir(), '.vaso', 'baselines'))).filter(f => f.startsWith('latest-'));
    expect(files.sort()).toEqual(['latest-ops_10.0.0.1.json', 'latest-ops_10.0.0.2.json']);
  });

  it('exits 2 and does not claim success when a per-host report cannot be written', async () => {
    const { mkdtemp, mkdir, rm } = await import('node:fs/promises');
    const { join } = await import('node:path');
    const { tmpdir } = await import('node:os');
    const out = await mkdtemp(join(tmpdir(), 'vaso-out-'));
    // the report's path is taken by a directory: the write fails
    await mkdir(join(out, 'web.json'));
    const errors: string[] = [];
    vi.mocked(console.error).mockImplementation((...a: unknown[]) => { errors.push(a.map(String).join(' ')); });
    scanMultipleHosts.mockImplementationOnce((async (opts: { targets: Array<{ user?: string; host: string }>; onComplete?: (e: unknown) => Promise<void> }) => {
      const entries = opts.targets.map((target) => ({
        target, durationMs: 1,
        result: {
          timestamp: 't', vasoVersion: '1.3.1', host: 'web', totalScore: 100, totalGrade: 'A', fleetAverage: 100,
          summary: { critical: 0, warning: 0, info: 0, passed: 0, total: 0 }, agents: [],
        },
      }));
      for (const e of entries) await opts.onComplete?.(e);
      return entries;
    }) as never);
    const before = process.exitCode;
    try {
      await runScan({ format: 'json', host: ['ops@10.0.0.1'], outputDir: out });
      expect(process.exitCode).toBe(2);
      expect(errors.some(l => l.includes('Failed to write the report for ops@10.0.0.1'))).toBe(true);
      expect(errors.some(l => l.includes('Wrote 0 report(s)') && l.includes('1 could not be written'))).toBe(true);
    } finally {
      process.exitCode = before;
      await rm(out, { recursive: true, force: true });
    }
  });

  it('refuses two hosts with labels that would share files, before scanning', async () => {
    const { mkdtemp, writeFile, rm } = await import('node:fs/promises');
    const { join } = await import('node:path');
    const { tmpdir } = await import('node:os');
    const dir = await mkdtemp(join(tmpdir(), 'vaso-inv-'));
    const inv = join(dir, 'inv.yaml');
    await writeFile(inv, 'hosts:\n  - host: root@10.0.0.1\n    label: Prod\n  - host: root@10.0.0.2\n    label: prod\n');
    try {
      await expect(runScan({ format: 'json', inventory: inv })).rejects.toThrow(/would name the same files/);
      expect(scanMultipleHosts).not.toHaveBeenCalled();
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
