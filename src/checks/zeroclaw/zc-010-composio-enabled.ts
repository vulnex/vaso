import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

export const zc010 = defineCheck({
  id: 'ZC-010',
  name: 'Composio Integration Enabled',
  category: 'zeroclaw',
  severity: 'info',
  description: 'Detect Composio integration enabled — grants access to 1000+ OAuth apps, large attack surface',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
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

    return h.fromEvidence(evidence, {
      passed: 'Composio integration is not enabled',
      failed: () => 'Composio integration is enabled — large OAuth attack surface',
    });
  },
});
