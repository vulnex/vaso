import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getSkillFiles } from '../../core/utils.js';

export const ioc008: CheckModule = {
  id: 'IOC-008',
  name: 'VirusTotal Cross-Reference',
  category: 'ioc',
  severity: 'critical',
  description: 'SHA-256 hash skill files and check against VirusTotal API (opt-in via VIRUSTOTAL_API_KEY)',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const apiKey = process.env['VIRUSTOTAL_API_KEY'];
    if (!apiKey) {
      return {
        id: 'IOC-008',
        name: 'VirusTotal Cross-Reference',
        category: 'ioc',
        severity: 'critical',
        passed: true,
        message: 'VirusTotal check skipped — no VIRUSTOTAL_API_KEY set',
      };
    }

    const skillsDir = ctx.installation.skillsDir;
    if (!skillsDir) {
      return { id: 'IOC-008', name: 'VirusTotal Cross-Reference', category: 'ioc', severity: 'critical', passed: true, message: 'No skills directory found' };
    }

    const evidence: Evidence[] = [];
    const files = ctx.skillFiles ?? await getSkillFiles(skillsDir);

    for (const file of files) {
      try {
        const content = await readFile(file);
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
        // 404 = not in VT database = not flagged; other errors ignored
      } catch {
        // Network errors, rate limits, etc. — skip file
      }
    }

    return {
      id: 'IOC-008',
      name: 'VirusTotal Cross-Reference',
      category: 'ioc',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No skill files flagged by VirusTotal'
        : `${evidence.length} file(s) flagged as malicious by VirusTotal`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
