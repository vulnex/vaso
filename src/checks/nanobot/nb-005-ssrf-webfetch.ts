import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';

export const nb005 = defineCheck({
  id: 'NB-005',
  name: 'WebFetchTool SSRF Risk',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check if WebFetchTool allows requests to localhost or private IPs (SSRF risk)',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence = [];
    for (const config of ctx.configs) {
      const webFetch = getNestedValue(config.data, 'tools.webFetch')
        ?? getNestedValue(config.data, 'webFetchTool');

      if (!webFetch || typeof webFetch !== 'object') continue;

      const toolConfig = webFetch as Record<string, unknown>;
      const blockedHosts = toolConfig.blockedHosts;
      const allowedHosts = toolConfig.allowedHosts;

      if (!blockedHosts && !allowedHosts) {
        evidence.push({
          file: config.filePath,
          detail: 'WebFetchTool has no blockedHosts or allowedHosts — SSRF to localhost/internal IPs is possible',
        });
      } else if (Array.isArray(blockedHosts) && blockedHosts.length === 0) {
        evidence.push({
          file: config.filePath,
          detail: 'WebFetchTool blockedHosts is empty — no host restrictions enforced',
        });
      } else if (Array.isArray(allowedHosts) && allowedHosts.length === 0) {
        evidence.push({
          file: config.filePath,
          detail: 'WebFetchTool allowedHosts is empty — no requests will succeed but config may be misconfigured',
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'WebFetchTool has host restrictions configured',
      failed: () => 'WebFetchTool lacks host restrictions — SSRF risk to localhost/private IPs',
      fixable: true,
      fixDescription: 'Add blockedHosts with localhost, 127.0.0.1, 169.254.169.254, and private IP ranges to WebFetchTool config',
    });
  },

  async fix(ctx) {
    const blockedHosts = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254', '10.*', '172.16.*', '192.168.*'];
    return fixFirstConfig(ctx.configs, {
      checkId: 'NB-005',
      path: 'tools.webFetch.blockedHosts',
      value: blockedHosts,
      message: 'Added SSRF-blocking host list to WebFetchTool',
      noConfigMessage: 'No JSON config file found',
    });
  },
});
