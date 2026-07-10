import { randomBytes } from 'node:crypto';
import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

export const ic004 = defineCheck({
  id: 'IC-004',
  name: 'Gateway Auth Token Missing',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check if GATEWAY_AUTH_TOKEN is set — ephemeral random tokens are not persistent across restarts',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      const token =
        (config.data.GATEWAY_AUTH_TOKEN as string | undefined) ??
        (getNestedValue(config.data, 'gateway.auth_token') as string | undefined) ??
        (getNestedValue(config.data, 'gateway.authToken') as string | undefined);

      if (!token || token.trim() === '') {
        evidence.push({
          file: config.filePath,
          detail: 'GATEWAY_AUTH_TOKEN is not set or empty — gateway uses ephemeral random tokens that are not persistent',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Gateway auth token is explicitly configured',
      failed: () => 'Gateway auth token is not set — ephemeral tokens reset on restart',
      fixable: true,
      fixDescription: 'Set a persistent GATEWAY_AUTH_TOKEN in .env or gateway.auth_token in config.toml',
    });
  },

  async fix(ctx) {
    const token = randomBytes(32).toString('hex');
    return fixFirstConfig(ctx.configs, {
      checkId: 'IC-004',
      env: 'GATEWAY_AUTH_TOKEN',
      path: 'gateway.auth_token',
      value: token,
      message: 'Generated and set persistent GATEWAY_AUTH_TOKEN',
    });
  },
});
