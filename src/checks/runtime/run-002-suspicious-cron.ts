import { execSync } from 'node:child_process';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const SUSPICIOUS_KEYWORDS = [
  'openclaw', 'nanoclaw', 'picoclaw', 'claw', 'moltbot', 'clawdbot',
  'skill', 'agent',
];

export const run002: CheckModule = {
  id: 'RUN-002',
  name: 'Suspicious Cron Entries',
  category: 'runtime',
  severity: 'warning',
  description: 'Check for cron entries referencing agent paths',
  supportedPlatforms: ['darwin', 'linux'],

  async run(_ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    try {
      const crontab = execSync('crontab -l 2>/dev/null', { encoding: 'utf-8', timeout: 5000 });
      const lines = crontab.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line || line.startsWith('#')) continue;

        const lower = line.toLowerCase();
        for (const keyword of SUSPICIOUS_KEYWORDS) {
          if (lower.includes(keyword)) {
            evidence.push({
              file: 'crontab',
              line: i + 1,
              snippet: line.slice(0, 120),
              detail: `Cron entry references "${keyword}"`,
            });
            break;
          }
        }
      }
    } catch {
      // No crontab or access denied
    }

    return {
      id: 'RUN-002',
      name: 'Suspicious Cron Entries',
      category: 'runtime',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No suspicious cron entries found'
        : `Found ${evidence.length} suspicious cron entry/entries`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
