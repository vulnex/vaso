import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';

export const zc005 = defineCheck({
  id: 'ZC-005',
  name: 'Full Autonomy Mode',
  category: 'zeroclaw',
  severity: 'critical',
  description: 'Detect autonomy.level=full which bypasses all approval gates for tool execution',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      const autonomyLevel = getNestedValue(config.data, 'autonomy.level');

      if (autonomyLevel === 'full') {
        evidence.push({
          file: config.filePath,
          detail: 'autonomy.level=full — all tool executions bypass approval gates',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Autonomy level is not set to full',
      failed: () => 'Full autonomy mode enabled — all approval gates bypassed',
      fixable: true,
      fixDescription: 'Set autonomy.level to "supervised" or "restricted" to require approval for tool execution',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: 'ZC-005',
      path: 'autonomy.level',
      value: 'supervised',
      message: 'Set autonomy.level=supervised',
      noConfigMessage: 'No TOML config file found',
    });
  },
});
