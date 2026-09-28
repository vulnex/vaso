import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { asRecord, atomicConfigs } from './shared.js';

export const at008 = defineCheck({
  id: 'AT-008',
  name: 'Atomic Agent Webhook Without Secret',
  category: 'atomic-agent',
  severity: 'warning',
  description: 'webhooks.<name> defined without a `secret`. POST /api/webhooks/<name> renders the request body into a user message and runs a full agent turn with the operator\'s tools; `atomic-agent serve` requires no API key by default (not even on a non-loopback --host), so the per-webhook x-webhook-secret is often the only thing between a caller and the agent.',
  supportedAgents: ['atomic-agent'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of atomicConfigs(ctx.configs)) {
      for (const [name, raw] of Object.entries(asRecord(config.data.webhooks) ?? {})) {
        const hook = asRecord(raw);
        if (!hook) continue;
        if (typeof hook.secret === 'string' && hook.secret.length > 0) continue;
        evidence.push({
          file: config.filePath,
          snippet: `webhooks.${name}: no secret`,
          detail: `Webhook "${name}" accepts any caller who can reach the HTTP service (when serve runs without --api-key) — its body becomes a prompt the agent acts on`,
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Atomic Agent webhooks require a shared secret',
      failed: (n) => `${n} Atomic Agent webhook(s) have no secret`,
      fixDescription: 'Set webhooks.<name>.secret (sent as the x-webhook-secret header) and always run `atomic-agent serve` with --api-key / ATOMIC_AGENT_API_KEY',
    });
  },
});
