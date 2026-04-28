import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const STALE_DAYS = 7;

interface PairingRecord {
  channel?: string;
  senderId?: string;
  senderName?: string;
  requestedAt?: string;
}

export const ly005 = defineCheck({
  id: 'LY-005',
  name: 'Stale Pending DM Pairings',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect pending DM-pairing requests older than 7 days — abandoned approvals accumulate and obscure new requests, weakening the human-in-the-loop signal.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const path = join(ctx.installation.installDir, 'pairing.json');
    if (!(await ctx.fs.access(path))) return h.passed('pairing.json not present');

    const evidence: Evidence[] = [];
    try {
      const raw = await ctx.fs.readFile(path);
      const data = JSON.parse(raw) as { pending?: PairingRecord[] };
      const pending = Array.isArray(data.pending) ? data.pending : [];
      const cutoff = Date.now() - STALE_DAYS * 24 * 60 * 60 * 1000;

      const stale = pending.filter(p => {
        if (!p.requestedAt) return false;
        const ts = Date.parse(p.requestedAt);
        return Number.isFinite(ts) && ts < cutoff;
      });

      if (stale.length > 0) {
        evidence.push({
          file: path,
          detail: `${stale.length} pending pairing request(s) older than ${STALE_DAYS} days — review and prune`,
        });
      }
    } catch {
      // Malformed JSON or read error — silently pass; LY-004 covers perm issues
    }

    return h.fromEvidence(evidence, {
      passed: 'No stale pending pairings',
      failed: () => 'Stale pending pairings detected',
      fixDescription: 'Review pending requests with `lyrie pairing list` and either approve or remove them',
    });
  },
});
