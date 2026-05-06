import { createHash } from 'node:crypto';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getSkillFiles } from '../../core/utils.js';

export const ioc008 = defineCheck({
  id: 'IOC-008',
  name: 'VirusTotal Cross-Reference',
  category: 'ioc',
  severity: 'critical',
  description: 'SHA-256 hash skill files and check against VirusTotal API (opt-in via VIRUSTOTAL_API_KEY)',

  async run(ctx, h) {
    const apiKey = process.env['VIRUSTOTAL_API_KEY'];
    if (!apiKey) return h.passed('VirusTotal check skipped — no VIRUSTOTAL_API_KEY set');

    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) return h.passed('No skills directory found');

    const evidence: Evidence[] = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir, ctx.fs);

    for (const file of files) {
      try {
        const content = await ctx.fs.readFile(file);
        const hash = createHash('sha256').update(content).digest('hex');

        const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
          headers: { 'x-apikey': apiKey },
        });

        if (response.status === 200) {
          const data = await response.json() as { data?: { attributes?: { last_analysis_stats?: { malicious?: number } } } };
          const malicious = data?.data?.attributes?.last_analysis_stats?.malicious ?? 0;
          if (malicious > 0) {
            evidence.push({
              file,
              detail: `VirusTotal: ${malicious} engine(s) flagged this file as malicious (SHA-256: ${hash})`,
            });
          }
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      passed: 'No skill files flagged by VirusTotal',
      failed: (n) => `${n} file(s) flagged as malicious by VirusTotal`,
    });
  },
});
