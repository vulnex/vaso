import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { updateEnvFile } from '../../remediation/config-writer.js';

export const ly011 = defineCheck({
  id: 'LY-011',
  name: 'WebChat Permissive Origin Allowlist',
  category: 'lyrie',
  severity: 'warning',
  description: 'Detect WebChat enabled with LYRIE_WEBCHAT_ORIGINS unset or wildcard — invites cross-origin requests from any browser context.',
  supportedAgents: ['lyrie'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      const port = config.data.LYRIE_WEBCHAT_PORT as string | undefined;
      if (!port) continue;

      const origins = (config.data.LYRIE_WEBCHAT_ORIGINS as string | undefined)?.trim();
      if (!origins) {
        evidence.push({
          file: config.filePath,
          detail: 'WebChat enabled but LYRIE_WEBCHAT_ORIGINS is unset — origin allowlist defaults to permissive',
        });
      } else if (origins === '*' || origins.split(',').map(s => s.trim()).includes('*')) {
        evidence.push({
          file: config.filePath,
          detail: 'LYRIE_WEBCHAT_ORIGINS includes "*" — any origin can connect',
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'WebChat origin allowlist is restrictive or WebChat is disabled',
      failed: () => 'WebChat origin allowlist is unset or wildcard',
      fixable: true,
      fixDescription: 'Set LYRIE_WEBCHAT_ORIGINS to an explicit comma-separated list (e.g. https://your-app.example.com)',
    });
  },

  async fix(ctx) {
    for (const config of ctx.configs) {
      if (config.format === 'env' && config.data.LYRIE_WEBCHAT_PORT) {
        await updateEnvFile(config.filePath, 'LYRIE_WEBCHAT_ORIGINS', 'http://127.0.0.1');
        return { checkId: 'LY-011', applied: true, message: 'Set LYRIE_WEBCHAT_ORIGINS=http://127.0.0.1 — adjust to your real frontend origin' };
      }
    }
    return { checkId: 'LY-011', applied: false, message: 'No .env file with WebChat configured found' };
  },
});
