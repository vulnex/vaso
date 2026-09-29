import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { envString, envTrue, isConfigured, lyrieEnvConfigs } from './env.js';

/** Cloud keys ModelRouter.initialize() registers (packages/core/src/index.ts). */
const CLOUD_PROVIDER_KEYS = [
  'ANTHROPIC_API_KEY',
  'OPENAI_API_KEY',
  'GOOGLE_API_KEY',
  'XAI_API_KEY',
  'MINIMAX_API_KEY',
] as const;

/**
 * LYRIE_MODE=local and LYRIE_REQUIRE_LOCAL=true are parsed by
 * packages/core/src/config.ts, but in 3.4.0 the ModelRouter only receives
 * the provider keys and LYRIE_PREFER_LOCAL — it registers every cloud
 * provider with a key and routes to it whenever no local model fits.
 */
export const ly007 = defineCheck({
  id: 'LY-007',
  name: 'Local-Only Mode Not Enforced With Cloud Keys Present',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect LYRIE_MODE=local or LYRIE_REQUIRE_LOCAL=true alongside cloud provider API keys in the same .env. Lyrie 3.4.0 does not enforce either setting: the model router registers every provider that has a key and sends prompts (and tool output) to the cloud whenever no local model is selected, contrary to the operator\'s local-only intent.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of lyrieEnvConfigs(ctx.configs)) {
      const localMode = envString(config, 'LYRIE_MODE')?.toLowerCase() === 'local';
      const requireLocal = envTrue(config, 'LYRIE_REQUIRE_LOCAL');
      if (!localMode && !requireLocal) continue;

      const keys = CLOUD_PROVIDER_KEYS.filter(k => isConfigured(envString(config, k)));
      if (keys.length === 0) continue;

      const intent = requireLocal ? 'LYRIE_REQUIRE_LOCAL=true' : 'LYRIE_MODE=local';
      evidence.push({
        file: config.filePath,
        snippet: intent,
        detail: `${intent} but ${keys.join(', ')} ${keys.length === 1 ? 'is' : 'are'} set — Lyrie 3.4.0 still routes to these cloud providers`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'No local-only setting contradicted by configured cloud provider keys',
      failed: () => 'Local-only mode configured but cloud provider keys remain usable',
      fixDescription: 'Remove the cloud *_API_KEY entries from the .env to actually keep inference local (and set LYRIE_PREFER_LOCAL=true)',
    });
  },
});
