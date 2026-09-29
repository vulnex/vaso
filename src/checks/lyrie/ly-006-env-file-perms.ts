import type { Evidence, ParsedConfig } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUnreachable, queryPermissions, readableByOthers } from '../../core/permissions.js';
import { isRealValue } from './env.js';

/** Env/JSON keys holding credentials (provider keys, channel tokens and
 *  secrets, backend tokens, GitHub/licence keys from the Python CLI). */
const SECRET_KEY = /(_API_KEY|_TOKEN|_SECRET|_PASS|_PASSWORD|_LICENSE_KEY|_MEMORY_KEY|_ENCRYPT_KEY)$/;

function secretKeys(config: ParsedConfig): string[] {
  const data = config.data as Record<string, unknown>;
  if (!data || typeof data !== 'object') return [];
  return Object.keys(data).filter(k => SECRET_KEY.test(k) && isRealValue(data[k]));
}

export const ly006 = defineCheck({
  id: 'LY-006',
  name: 'Lyrie Secrets File Readable by Other Users',
  category: 'lyrie',
  severity: 'critical',
  description: 'Detect Lyrie secret stores holding real credentials — the checkout .env (provider API keys, channel bot tokens) and ~/.lyrie/config.json (Python CLI key store) — whose mode lets group or other users read them. `cp .env.example .env` leaves the file at the umask default (typically 0644/0664).',
  supportedAgents: ['lyrie'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      if (config.format !== 'env' && config.format !== 'json') continue;
      const keys = secretKeys(config);
      if (keys.length === 0) continue;

      try {
        const perms = await queryPermissions(ctx.fs, config.filePath);
        if (perms !== 'unsupported' && readableByOthers(perms)) {
          const shown = keys.slice(0, 5).join(', ') + (keys.length > 5 ? `, +${keys.length - 5} more` : '');
          evidence.push({
            file: config.filePath,
            snippet: perms.description,
            detail: `Readable by ${perms.worldRead ? 'all local users' : 'the file\'s group'} and holds ${keys.length} credential(s): ${shown}`,
          });
        }
      } catch {
        // Can't stat — skip
      }
    }
    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'Lyrie secret files are private to their owner',
      failed: n => `${n} Lyrie secret file(s) readable by other users`,
      fixDescription: 'Run `chmod 600 <checkout>/.env ~/.lyrie/config.json` and rotate any key that other users could have read',
    });
  },
});
