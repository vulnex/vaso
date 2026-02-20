import { createConnection } from 'node:net';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const AGENT_PORTS = [18789, 18790, 3000, 8080, 8443];

function checkPort(host: string, port: number, timeout = 1000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port });
    socket.setTimeout(timeout);
    socket.on('connect', () => { socket.destroy(); resolve(true); });
    socket.on('timeout', () => { socket.destroy(); resolve(false); });
    socket.on('error', () => { socket.destroy(); resolve(false); });
  });
}

export const net004: CheckModule = {
  id: 'NET-004',
  name: 'Agent Service Port Scan',
  category: 'network',
  severity: 'info',
  description: 'Check for agent services listening on known ports',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    const checks = await Promise.allSettled(
      AGENT_PORTS.map(async (port) => {
        const open = await checkPort('127.0.0.1', port);
        if (open) {
          evidence.push({
            file: 'localhost',
            detail: `Port ${port} is open on localhost`,
          });
        }
      })
    );

    return {
      id: 'NET-004',
      name: 'Agent Service Port Scan',
      category: 'network',
      severity: 'info',
      passed: true, // Info-only, doesn't fail
      message: evidence.length === 0
        ? 'No agent services detected on known ports'
        : `Found ${evidence.length} open agent port(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
