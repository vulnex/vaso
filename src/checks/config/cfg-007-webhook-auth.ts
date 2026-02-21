import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg007: CheckModule = {
  id: 'CFG-007',
  name: 'Webhook Missing Auth',
  category: 'config',
  severity: 'warning',
  description: 'Check if webhooks are configured without authentication',

  async run(ctx: ScanContext): Promise<CheckResult> {
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

    return {
      id: 'CFG-007',
      name: 'Webhook Missing Auth',
      category: 'config',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No unauthenticated webhooks found'
        : `${evidence.length} webhook(s) configured without authentication`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
