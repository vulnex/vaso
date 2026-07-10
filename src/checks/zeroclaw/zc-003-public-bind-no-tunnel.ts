import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';

export const zc003 = defineCheck({
  id: 'ZC-003',
  name: 'Public Bind Without Tunnel',
  category: 'zeroclaw',
  severity: 'critical',
  description: 'Detect allow_public_bind=true combined with no tunnel provider configured',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      const publicBind = getNestedValue(config.data, 'security.allow_public_bind')
        ?? getNestedValue(config.data, 'allow_public_bind');
      const tunnelProvider = getNestedValue(config.data, 'tunnel.provider');

      if (publicBind === true || publicBind === 'true') {
        if (!tunnelProvider || tunnelProvider === 'none') {
          evidence.push({
            file: config.filePath,
            detail: `allow_public_bind=true with tunnel.provider=${tunnelProvider ?? 'not set'} — server is directly exposed to the internet`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Public bind is disabled or a tunnel provider is configured',
      failed: () => 'Server is directly exposed — public bind enabled without tunnel',
      fixable: true,
      fixDescription: 'Set tunnel.provider to a supported provider (e.g., cloudflare, ngrok) or disable allow_public_bind',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: 'ZC-003',
      path: 'security.allow_public_bind',
      value: false,
      message: 'Set security.allow_public_bind=false',
      noConfigMessage: 'No TOML config file found',
    });
  },
});
