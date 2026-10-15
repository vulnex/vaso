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
});
