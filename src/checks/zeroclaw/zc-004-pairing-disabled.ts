import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';

export const zc004 = defineCheck({
  id: 'ZC-004',
  name: 'Pairing Disabled',
  category: 'zeroclaw',
  severity: 'warning',
  description: 'Detect require_pairing=false which allows unauthenticated device connections',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      const requirePairing =
        getNestedValue(config.data, 'security.require_pairing') ??
        getNestedValue(config.data, 'require_pairing') ??
        config.data.REQUIRE_PAIRING;

      if (requirePairing === false || requirePairing === 'false') {
        evidence.push({
          file: config.filePath,
          detail: 'require_pairing=false — any device can connect without authentication',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Device pairing is required',
      failed: () => 'Device pairing is disabled — unauthenticated connections allowed',
      fixable: true,
      fixDescription: 'Set require_pairing=true to enforce device authentication',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: 'ZC-004',
      path: 'require_pairing',
      value: true,
      message: 'Set require_pairing=true',
      noConfigMessage: 'No TOML config file found',
    });
  },
});
