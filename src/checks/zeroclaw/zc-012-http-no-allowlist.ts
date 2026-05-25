import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

export const zc012 = defineCheck({
  id: 'ZC-012',
  name: 'HTTP Tool No Allowlist',
  category: 'zeroclaw',
  severity: 'warning',
  description: 'Detect HTTP request tool enabled without domain restrictions',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      const httpEnabled = getNestedValue(config.data, 'tools.http.enabled');
      const allowedDomains = getNestedValue(config.data, 'tools.http.allowed_domains');

      if (httpEnabled === true || httpEnabled === 'true') {
        if (!allowedDomains || (Array.isArray(allowedDomains) && allowedDomains.length === 0)) {
          evidence.push({
            file: config.filePath,
            detail: 'tools.http.enabled=true without allowed_domains — agent can make requests to any domain',
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'HTTP tool has domain restrictions or is not enabled',
      failed: () => 'HTTP tool enabled without domain allowlist — unrestricted outbound requests',
      fixDescription: 'Set tools.http.allowed_domains to a list of trusted domains',
    });
  },
});
