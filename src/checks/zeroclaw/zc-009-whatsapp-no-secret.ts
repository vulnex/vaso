import { isAbsolute, join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { accessibleByOthers, markUnreachable, queryPermissions } from '../../core/permissions.js';
import { asRecord, isTrue, mainConfig } from './zc-config.js';

/**
 * Upstream now refuses unsigned WhatsApp Cloud webhooks (no app_secret → 401),
 * so the old "no HMAC secret" finding no longer exists. The remaining
 * WhatsApp exposure is WhatsApp Web mode: `session_path` holds the linked
 * device's session keys, and anyone who can read it can take over the account.
 */
export const zc009 = defineCheck({
  id: 'ZC-009',
  name: 'WhatsApp Web Session Store Exposed',
  category: 'zeroclaw',
  severity: 'critical',
  description:
    'Detect an enabled [channels.whatsapp.<alias>] in WhatsApp Web mode whose session_path (linked-device session keys) is accessible to other local users',
  supportedAgents: ['zeroclaw'],
  supportedPlatforms: ['linux', 'darwin'],

  async run(ctx, h) {
    const config = mainConfig(ctx.configs);
    if (!config) return h.passed('No ZeroClaw config.toml found');
    const whatsapp = asRecord(asRecord(config.data.channels)?.whatsapp);
    if (!whatsapp) return h.passed('No WhatsApp channel configured');

    const home = ctx.fs.homedir();
    const evidence: Evidence[] = [];
    for (const [alias, raw] of Object.entries(whatsapp)) {
      const inst = asRecord(raw);
      if (!inst || !isTrue(inst.enabled)) continue;
      if (typeof inst.session_path !== 'string' || !inst.session_path.trim()) continue;
      let p = inst.session_path.trim();
      if (p === '~' || p.startsWith('~/')) p = join(home, p.slice(1));
      if (!isAbsolute(p)) continue; // relative to the daemon's cwd — not resolvable statically
      try {
        const perms = await queryPermissions(ctx.fs, p);
        if (perms !== 'unsupported' && accessibleByOthers(perms)) {
          evidence.push({
            file: p,
            detail: `channels.whatsapp.${alias}.session_path is ${perms.octal} — WhatsApp Web session keys readable by other users (account takeover)`,
          });
        }
      } catch {
        // Session not created yet, or not visible to this scan.
      }
    }

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'No exposed WhatsApp Web session store',
      failed: (n) => `${n} WhatsApp Web session store(s) accessible to other users`,
      fixDescription: 'chmod 600 the session database (700 for a directory) and keep it under a private directory',
    });
  },
});
