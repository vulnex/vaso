import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

export const zc011 = defineCheck({
  id: 'ZC-011',
  name: 'Browser Tool No Allowlist',
  category: 'zeroclaw',
  severity: 'warning',
  description: 'Detect browser tool enabled without allowed_domains restriction',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      const browserEnabled = getNestedValue(config.data, 'tools.browser.enabled');
      const allowedDomains = getNestedValue(config.data, 'tools.browser.allowed_domains');

      if (browserEnabled === true || browserEnabled === 'true') {
        if (!allowedDomains || (Array.isArray(allowedDomains) && allowedDomains.length === 0)) {
          evidence.push({
            file: config.filePath,
            detail: 'tools.browser.enabled=true without allowed_domains — agent can browse any website',
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Browser tool has domain restrictions or is not enabled',
      failed: () => 'Browser tool enabled without domain allowlist — unrestricted web access',
      fixable: true,
      fixDescription: 'Set tools.browser.allowed_domains to a list of trusted domains',
    });
  },

  async fix() {
    return { checkId: 'ZC-011', applied: false, message: 'Manual action required: set tools.browser.allowed_domains to a list of trusted domains' };
  },
});
