import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const zc012: CheckModule = {
  id: 'ZC-012',
  name: 'HTTP Tool No Allowlist',
  category: 'zeroclaw',
  severity: 'warning',
  description: 'Detect HTTP request tool enabled without domain restrictions',
  supportedAgents: ['zeroclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
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

    return {
      id: 'ZC-012',
      name: 'HTTP Tool No Allowlist',
      category: 'zeroclaw',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'HTTP tool has domain restrictions or is not enabled'
        : 'HTTP tool enabled without domain allowlist — unrestricted outbound requests',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set tools.http.allowed_domains to a list of trusted domains',
    };
  },
};
