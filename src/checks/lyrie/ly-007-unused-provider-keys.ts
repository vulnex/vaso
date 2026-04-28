import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const PROVIDER_KEYS = [
  'ANTHROPIC_API_KEY',
  'OPENAI_API_KEY',
  'GOOGLE_API_KEY',
  'XAI_API_KEY',
  'MINIMAX_API_KEY',
] as const;

export const ly007 = defineCheck({
  id: 'LY-007',
  name: 'Unused Provider API Keys',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect cloud-provider API keys configured while LYRIE_MODE=local — keys are unreachable but still present, expanding credential-theft surface for no functional reason.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      const mode = config.data.LYRIE_MODE as string | undefined;
      if (mode !== 'local') continue;

      for (const key of PROVIDER_KEYS) {
        const val = config.data[key] as string | undefined;
        if (val && val.trim() !== '' && !/^\$\{?[A-Z_]+\}?$/.test(val.trim())) {
          evidence.push({
            file: config.filePath,
            detail: `${key} is set while LYRIE_MODE=local — credential is unused at runtime`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No unused provider keys detected',
      failed: () => 'Cloud-provider keys configured while LYRIE_MODE=local',
      fixDescription: 'Remove unused *_API_KEY entries from .env, or set LYRIE_MODE=hybrid/cloud if you intend to use them',
    });
  },
});
