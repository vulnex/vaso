import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';
import { isTrue, mainConfig } from './zc-config.js';

export const zc010 = defineCheck({
  id: 'ZC-010',
  name: 'Composio Integration Enabled',
  category: 'zeroclaw',
  severity: 'info',
  description: 'Detect [composio] enabled=true — grants the agent 1000+ OAuth-connected apps, a large attack surface',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const config = mainConfig(ctx.configs);
    if (!config) return h.passed('No ZeroClaw config.toml found');
    const evidence: Evidence[] = [];
    // V3 key is composio.enabled (serde alias `enable`); pre-V3 used [integrations.composio].
    const enabled =
      getNestedValue(config.data, 'composio.enabled') ??
      getNestedValue(config.data, 'composio.enable') ??
      getNestedValue(config.data, 'integrations.composio.enabled');
    if (isTrue(enabled)) {
      evidence.push({
        file: config.filePath,
        detail: 'composio.enabled = true — access to 1000+ OAuth apps increases the blast radius of a prompt injection',
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'Composio integration is not enabled',
      failed: () => 'Composio integration is enabled — large OAuth attack surface',
    });
  },
});
