import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getIOCDatabase } from '../../ioc/database.js';

const IP_REGEX = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/g;

export const net005: CheckModule = {
  id: 'NET-005',
  name: 'Active Connection Monitoring',
  category: 'network',
  severity: 'critical',
  description: 'Check active network connections against known C2 IP addresses',
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const db = getIOCDatabase();
    const c2Set = new Set(db.c2Ips);

    let output = '';
    try {
      if (ctx.platform === 'darwin') {
        output = ctx.fs.execSync('netstat', ['-an', '-p', 'tcp'], { timeout: 5000 });
      } else {
        output = ctx.fs.execSync('ss', ['-tn'], { timeout: 5000 });
      }
    } catch {
      return {
        id: 'NET-005',
        name: 'Active Connection Monitoring',
        category: 'network',
        severity: 'critical',
        passed: true,
        message: 'Could not retrieve active connections',
      };
    }

    const lines = output.split('\n');
    for (const line of lines) {
      const lower = line.toLowerCase();
      if (!lower.includes('established') && !lower.includes('estab')) continue;

      const ips = line.match(IP_REGEX);
      if (!ips) continue;

      for (const ip of ips) {
        if (c2Set.has(ip)) {
          evidence.push({
            file: 'netstat',
            snippet: line.trim().slice(0, 120),
            detail: `Active connection to known C2 IP: ${ip}`,
          });
        }
      }
    }

    return {
      id: 'NET-005',
      name: 'Active Connection Monitoring',
      category: 'network',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No active connections to known C2 IP addresses'
        : `Found ${evidence.length} active connection(s) to known C2 IP addresses`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
