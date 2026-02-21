import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const zc011: CheckModule = {
  id: 'ZC-011',
  name: 'Browser Tool No Allowlist',
  category: 'zeroclaw',
  severity: 'warning',
  description: 'Detect browser tool enabled without allowed_domains restriction',
  supportedAgents: ['zeroclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
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

    return {
      id: 'ZC-011',
      name: 'Browser Tool No Allowlist',
      category: 'zeroclaw',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Browser tool has domain restrictions or is not enabled'
        : 'Browser tool enabled without domain allowlist — unrestricted web access',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set tools.browser.allowed_domains to a list of trusted domains',
    };
  },
};
