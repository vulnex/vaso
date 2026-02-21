import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const zc010: CheckModule = {
  id: 'ZC-010',
  name: 'Composio Integration Enabled',
  category: 'zeroclaw',
  severity: 'info',
  description: 'Detect Composio integration enabled — grants access to 1000+ OAuth apps, large attack surface',
  supportedAgents: ['zeroclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const composioEnabled = getNestedValue(config.data, 'integrations.composio.enabled');

      if (composioEnabled === true || composioEnabled === 'true') {
        evidence.push({
          file: config.filePath,
          detail: 'integrations.composio.enabled=true — access to 1000+ OAuth apps increases attack surface',
        });
      }
    }

    return {
      id: 'ZC-010',
      name: 'Composio Integration Enabled',
      category: 'zeroclaw',
      severity: 'info',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Composio integration is not enabled'
        : 'Composio integration is enabled — large OAuth attack surface',
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
