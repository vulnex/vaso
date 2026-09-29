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
});
