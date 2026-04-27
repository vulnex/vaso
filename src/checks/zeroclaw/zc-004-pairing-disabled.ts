import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { updateTomlFile } from '../../remediation/config-writer.js';

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
    for (const config of ctx.configs) {
      if (config.format === 'toml') {
        await updateTomlFile(config.filePath, 'require_pairing', true);
        return { checkId: 'ZC-004', applied: true, message: 'Set require_pairing=true' };
      }
    }
    return { checkId: 'ZC-004', applied: false, message: 'No TOML config file found' };
  },
});
