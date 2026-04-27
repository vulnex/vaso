import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg007 = defineCheck({
  id: 'CFG-007',
  name: 'Webhook Missing Auth',
  category: 'config',
  severity: 'warning',
  description: 'Check if webhooks are configured without authentication',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const webhooks = getNestedValue(config.data, 'webhooks') ??
                       getNestedValue(config.data, 'webhook');

      if (!webhooks) continue;

      const webhookList = Array.isArray(webhooks) ? webhooks : [webhooks];
      for (const wh of webhookList) {
        if (typeof wh === 'object' && wh !== null) {
          const hook = wh as Record<string, unknown>;
          if (!hook.secret && !hook.auth && !hook.token && !hook.hmac) {
            evidence.push({
              file: config.filePath,
              detail: `Webhook "${hook.url ?? hook.endpoint ?? 'unknown'}" has no authentication`,
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No unauthenticated webhooks found',
      failed: (n) => `${n} webhook(s) configured without authentication`,
    });
  },
});
