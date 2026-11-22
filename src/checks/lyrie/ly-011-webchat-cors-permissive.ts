import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { envFile, envString, envTrue, lyrieMergedEnvs } from './env.js';

/**
 * gateway/src/webchat/bot.ts isWebChatOriginAllowed(): an empty/unset
 * allowlist or a "*" entry accepts every Origin.
 */
export const ly011 = defineCheck({
  id: 'LY-011',
  name: 'WebChat Permissive Origin Allowlist',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect LYRIE_WEBCHAT_ENABLED=true with LYRIE_WEBCHAT_ORIGINS unset or containing "*" — Lyrie\'s origin check then accepts browser handshakes from any web page (cross-site WebSocket hijacking of the agent chat).',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of lyrieMergedEnvs(ctx.configs)) {
      if (!envTrue(config, 'LYRIE_WEBCHAT_ENABLED')) continue;

      const origins = (envString(config, 'LYRIE_WEBCHAT_ORIGINS') ?? '')
        .split(',').map(s => s.trim()).filter(Boolean);
      if (origins.length === 0) {
        evidence.push({
          file: envFile(config, 'LYRIE_WEBCHAT_ENABLED'),
          detail: 'WebChat enabled but LYRIE_WEBCHAT_ORIGINS is unset — every origin is accepted',
        });
      } else if (origins.includes('*')) {
        evidence.push({
          file: envFile(config, 'LYRIE_WEBCHAT_ORIGINS'),
          snippet: `LYRIE_WEBCHAT_ORIGINS=${origins.join(',')}`,
          detail: 'LYRIE_WEBCHAT_ORIGINS contains "*" — every origin is accepted',
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'WebChat is disabled or restricted to explicit origins',
      failed: () => 'WebChat accepts connections from any origin',
      fixDescription: 'Set LYRIE_WEBCHAT_ORIGINS to the exact origin(s) of your chat frontend, comma-separated (e.g. https://chat.example.com)',
    });
  },
});
