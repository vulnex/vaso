import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const gem006 = defineCheck({
  id: 'GEM-006',
  name: 'Gemini Sandbox Network Access Enabled',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect when tools.sandboxNetworkAccess is enabled — sandboxed tools can reach the network',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const tools = config.data.tools as Record<string, unknown> | undefined;
      if (!tools || typeof tools !== 'object') continue;
      if (tools.sandboxNetworkAccess === true) {
        evidence.push({
          file: config.filePath,
          snippet: 'tools.sandboxNetworkAccess = true',
          detail: 'Sandboxed tools can reach the network — exfiltration paths exist even when sandbox is on',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Gemini sandbox network access is restricted',
      failed: () => 'Gemini sandboxed tools have network access',
      fixDescription: 'Set tools.sandboxNetworkAccess: false in ~/.gemini/settings.json unless your tools genuinely need it',
    });
  },
});
