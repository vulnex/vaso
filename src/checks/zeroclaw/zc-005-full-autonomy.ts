import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const zc005: CheckModule = {
  id: 'ZC-005',
  name: 'Full Autonomy Mode',
  category: 'zeroclaw',
  severity: 'critical',
  description: 'Detect autonomy.level=full which bypasses all approval gates for tool execution',
  supportedAgents: ['zeroclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
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

    return {
      id: 'ZC-005',
      name: 'Full Autonomy Mode',
      category: 'zeroclaw',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Autonomy level is not set to full'
        : 'Full autonomy mode enabled — all approval gates bypassed',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set autonomy.level to "supervised" or "restricted" to require approval for tool execution',
    };
  },
};
