import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';

const SUSPICIOUS_KEYWORDS = [
  'claw',
  'nanobot',
  'moltbot',
  'hermes-agent',
];

export const run002 = defineCheck({
  id: 'RUN-002',
  name: 'Suspicious Cron Entries',
  category: 'runtime',
  severity: 'warning',
  description: 'Check for cron entries referencing agent paths',
  excludedAgents: CODING_AGENTS,
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    try {
      const crontab = ctx.fs.execSync('crontab', ['-l'], { timeout: 5000 });
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

    return h.fromEvidence(evidence, {
      passed: 'No suspicious cron entries found',
      failed: (n) => `Found ${n} suspicious cron entry/entries`,
    });
  },
});
