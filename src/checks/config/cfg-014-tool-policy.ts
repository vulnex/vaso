import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg014: CheckModule = {
  id: 'CFG-014',
  name: 'Tool Policy Permissive',
  category: 'config',
  severity: 'warning',
  description: 'Check if the tool execution policy is too permissive',

  async run(ctx: ScanContext): Promise<CheckResult> {
    for (const config of ctx.configs) {
      const toolPolicy = getNestedValue(config.data, 'tools.policy') ??
                         getNestedValue(config.data, 'security.toolPolicy') ??
                         getNestedValue(config.data, 'skillPolicy');

      if (toolPolicy === 'allow_all' || toolPolicy === 'permissive' || toolPolicy === 'unrestricted') {
        return {
          id: 'CFG-014',
          name: 'Tool Policy Permissive',
          category: 'config',
          severity: 'warning',
          passed: false,
          message: 'Tool policy is permissive — any skill/tool can be executed without approval',
          evidence: [{ file: config.filePath, detail: `Tool policy: ${String(toolPolicy)}` }],
        };
      }
    }

    return {
      id: 'CFG-014',
      name: 'Tool Policy Permissive',
      category: 'config',
      severity: 'warning',
      passed: true,
      message: 'Tool policy is not overly permissive',
    };
  },
};
