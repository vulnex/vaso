import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { lyrieStateDir } from '../../adapters/lyrie.js';

const STALE_DAYS = 7;

export const ly005 = defineCheck({
  id: 'LY-005',
  name: 'Stale Pending DM Pairings',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect pending DM-pairing requests in ~/.lyrie/pairing.json older than 7 days — pairing codes never expire in Lyrie 3.4.0, so abandoned requests stay approvable indefinitely and obscure new ones.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const path = join(lyrieStateDir(ctx.fs), 'pairing.json');
    if (!(await ctx.fs.access(path))) return h.passed('pairing.json not present');

    const evidence: Evidence[] = [];
    try {
      const data = JSON.parse(await ctx.fs.readFile(path)) as { pending?: unknown };
      const pending = Array.isArray(data?.pending) ? data.pending : [];
      const cutoff = Date.now() - STALE_DAYS * 24 * 60 * 60 * 1000;

      const stale = pending.filter(p => {
        if (!p || typeof p !== 'object') return false;
        const requestedAt = (p as Record<string, unknown>).requestedAt;
        if (typeof requestedAt !== 'string') return false;
        const ts = Date.parse(requestedAt);
        return Number.isFinite(ts) && ts < cutoff;
      });

      if (stale.length > 0) {
        evidence.push({
          file: path,
          detail: `${stale.length} pending pairing request(s) older than ${STALE_DAYS} days — their codes are still approvable`,
        });
      }
    } catch {
      // Malformed JSON or unreadable — LY-004 covers permissions
    }

    return h.fromEvidence(evidence, {
      passed: 'No stale pending pairings',
      failed: () => 'Stale pending pairings detected',
      fixDescription: 'In the Lyrie checkout run `bun run pairing list`, then approve legitimate senders (`bun run pairing approve <channel> <code>`) and remove the rest from ~/.lyrie/pairing.json',
    });
  },
});
