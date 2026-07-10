import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg013 = defineCheck({
  id: 'CFG-013',
  name: 'DM Policy Open',
  category: 'config',
  severity: 'warning',
  description: 'Check if direct message policy allows unrestricted messaging',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    for (const config of ctx.configs) {
      const dmPolicy = getNestedValue(config.data, 'dm.policy') ??
                       getNestedValue(config.data, 'messaging.dm') ??
                       getNestedValue(config.data, 'directMessage.policy');

      if (dmPolicy === 'open' || dmPolicy === 'unrestricted' || dmPolicy === 'allow_all') {
        return h.result({
          passed: false,
          message: 'DM policy is set to open — anyone can message the agent directly',
          evidence: [{ file: config.filePath, detail: `DM policy: ${String(dmPolicy)}` }],
          fixable: true,
          fixDescription: 'Set DM policy to restricted or allowlist-only',
        });
      }
    }

    return h.passed('DM policy is not set to open');
  },

  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: 'CFG-013',
      env: 'DM_POLICY',
      path: 'dm.policy',
      value: 'restricted',
      message: 'Set DM policy to restricted',
      noConfigMessage: 'No config file found',
    });
  },
});
