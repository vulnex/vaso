import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const net003: CheckModule = {
  id: 'NET-003',
  name: 'Reverse Proxy Bypass',
  category: 'network',
  severity: 'warning',
  description: 'Check if trusted-proxy is set without proper IP restriction',
  excludedAgents: CODING_AGENTS,

  async run(ctx: ScanContext): Promise<CheckResult> {
    for (const config of ctx.configs) {
      const trustProxy = getNestedValue(config.data, 'trustProxy') ??
                         getNestedValue(config.data, 'gateway.trustProxy') ??
                         getNestedValue(config.data, 'proxy.trust');

      if (trustProxy === true || trustProxy === 'all') {
        return {
          id: 'NET-003',
          name: 'Reverse Proxy Bypass',
          category: 'network',
          severity: 'warning',
          passed: false,
          message: 'Trusted proxy is set to trust all — IP spoofing via X-Forwarded-For is possible',
          evidence: [{ file: config.filePath, detail: `trustProxy: ${String(trustProxy)}` }],
        };
      }
    }

    return {
      id: 'NET-003',
      name: 'Reverse Proxy Bypass',
      category: 'network',
      severity: 'warning',
      passed: true,
      message: 'No unrestricted proxy trust detected',
    };
  },
};
