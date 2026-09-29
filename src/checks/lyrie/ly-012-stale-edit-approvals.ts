import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { lyrieStateDir } from '../../adapters/lyrie.js';

const STALE_HOURS = 24;

export const ly012 = defineCheck({
  id: 'LY-012',
  name: 'Stale Pending Edit Approvals',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect pending diff-view edit plans in ~/.lyrie/edits.json older than 24 hours — a long approval queue signals operator inattention, and old plans approved later apply against file state that has drifted since they were reviewed.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const path = join(lyrieStateDir(ctx.fs), 'edits.json');
    if (!(await ctx.fs.access(path))) return h.passed('edits.json not present');

    const evidence: Evidence[] = [];
    try {
      const data = JSON.parse(await ctx.fs.readFile(path)) as { pending?: unknown };
      const pending = Array.isArray(data?.pending) ? data.pending : [];
      const cutoff = Date.now() - STALE_HOURS * 60 * 60 * 1000;

      const stale = pending.filter(p => {
        if (!p || typeof p !== 'object') return false;
        const createdAt = (p as Record<string, unknown>).createdAt;
        if (typeof createdAt !== 'string') return false;
        const ts = Date.parse(createdAt);
        return Number.isFinite(ts) && ts < cutoff;
      });

      if (stale.length > 0) {
        evidence.push({
          file: path,
          detail: `${stale.length} pending edit plan(s) older than ${STALE_HOURS} hours — re-review before approving`,
        });
      }
    } catch {
      // Malformed JSON or read error
    }

    return h.fromEvidence(evidence, {
      passed: 'No stale pending edit approvals',
      failed: () => 'Stale pending edit approvals detected',
      fixDescription: 'In the Lyrie checkout run `bun run edits list` and `bun run edits review <planId>`, then approve (`bun run edits approve <planId>`) or discard each plan',
    });
  },
});
