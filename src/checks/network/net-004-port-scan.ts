import { createConnection } from 'node:net';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';

const AGENT_PORTS = [18789, 18790, 3000, 8080, 8443, 17670];

function checkPort(host: string, port: number, timeout = 1000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port });
    socket.setTimeout(timeout);
    socket.on('connect', () => { socket.destroy(); resolve(true); });
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
    socket.on('error', () => { socket.destroy(); resolve(false); });
  });
}

export const net004 = defineCheck({
  id: 'NET-004',
  name: 'Agent Service Port Scan',
  category: 'network',
  severity: 'info',
  description: 'Check for agent services listening on known ports',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    // A live probe of 127.0.0.1 here would test the scanning machine, not the
    // host a snapshot came from.
    if (ctx.fs.kind === 'snapshot') {
      return h.passed('Not checked on remote/snapshot scans — listening ports are not collected');
    }
    const evidence: Evidence[] = [];

    await Promise.allSettled(
      AGENT_PORTS.map(async (port) => {
        const open = await checkPort('127.0.0.1', port);
        if (open) {
          evidence.push({ file: 'localhost', detail: `Port ${port} is open on localhost` });
        }
      })
    );

    // Info-only — never fails the scan, but reports findings
    return h.result({
      passed: true,
      message: evidence.length === 0
        ? 'No agent services detected on known ports'
        : `Found ${evidence.length} open agent port(s)`,
      evidence,
    });
  },
});
