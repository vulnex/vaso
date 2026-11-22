import { createHash } from 'node:crypto';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { skillFilesOf, noSkillsDirResult, unscannedRootsNote } from '../skills/skill-files.js';
import { readCappedBytes } from '../../core/file-limits.js';

const REQUEST_TIMEOUT_MS = 15_000;

export const ioc008 = defineCheck({
  id: 'IOC-008',
  name: 'VirusTotal Cross-Reference',
  category: 'ioc',
  severity: 'critical',
  description: 'SHA-256 hash skill files and check against VirusTotal API (opt-in via VIRUSTOTAL_API_KEY)',

  async run(ctx, h) {
    const apiKey = process.env['VIRUSTOTAL_API_KEY'];
    if (!apiKey) return h.passed('VirusTotal check skipped — no VIRUSTOTAL_API_KEY set');

    const noDir = noSkillsDirResult(ctx, h);
    if (noDir) return noDir;

    const evidence: Evidence[] = [];
    const files = await skillFilesOf(ctx);
    // A file is checked only when VirusTotal answered for it: 200 (known,
    // judged by its engines) or 404 (unknown to VirusTotal). Anything else —
    // a rejected key, the rate limit, a server error, no network — leaves it
    // unchecked, and the result says how many, never "clean".
    let unchecked = 0;
    let stopReason: string | undefined;
    let lastReason: string | undefined;

    for (const file of files) {
      if (stopReason) {
        unchecked++;
        continue;
      }
      try {
        const content = await readCappedBytes(ctx.fs, file);
        const hash = createHash('sha256').update(content).digest('hex');

        const response = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
          headers: { 'x-apikey': apiKey },
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
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
        } else if (response.status !== 404) {
          unchecked++;
          lastReason = `HTTP ${response.status}`;
          // Rate limit or rejected key: every further request fails the same way
          if (response.status === 429) stopReason = 'rate limit reached';
          else if (response.status === 401 || response.status === 403) stopReason = 'API key rejected';
        }
      } catch {
        unchecked++;
        lastReason = 'request failed';
      }
    }

    const note = unchecked > 0
      ? `; ${unchecked} of ${files.length} file(s) not checked (${stopReason ?? lastReason})`
      : '';
    return h.fromEvidence(evidence, {
      passed: unchecked > 0
        ? `No skill files flagged by VirusTotal${note}${unscannedRootsNote(ctx)}`
        : `No skill files flagged by VirusTotal${unscannedRootsNote(ctx)}`,
      failed: (n) => `${n} file(s) flagged as malicious by VirusTotal${note}`,
    });
  },
});
