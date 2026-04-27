import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg014 = defineCheck({
  id: 'CFG-014',
  name: 'Tool Policy Permissive',
  category: 'config',
  severity: 'warning',
  description: 'Check if the tool execution policy is too permissive',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    for (const config of ctx.configs) {
      const toolPolicy = getNestedValue(config.data, 'tools.policy') ??
                         getNestedValue(config.data, 'security.toolPolicy') ??
                         getNestedValue(config.data, 'skillPolicy');

      if (toolPolicy === 'allow_all' || toolPolicy === 'permissive' || toolPolicy === 'unrestricted') {
        return h.result({
          passed: false,
          message: 'Tool policy is permissive — any skill/tool can be executed without approval',
          evidence: [{ file: config.filePath, detail: `Tool policy: ${String(toolPolicy)}` }],
        });
      }
    }

    return h.passed('Tool policy is not overly permissive');
  },
});
