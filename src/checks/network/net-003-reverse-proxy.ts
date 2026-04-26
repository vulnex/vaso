import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const net003 = defineCheck({
  id: 'NET-003',
  name: 'Reverse Proxy Bypass',
  category: 'network',
  severity: 'warning',
  description: 'Check if trusted-proxy is set without proper IP restriction',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const trustProxy = getNestedValue(config.data, 'trustProxy') ??
                         getNestedValue(config.data, 'gateway.trustProxy') ??
                         getNestedValue(config.data, 'proxy.trust');

      if (trustProxy === true || trustProxy === 'all') {
        evidence.push({ file: config.filePath, detail: `trustProxy: ${String(trustProxy)}` });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No unrestricted proxy trust detected',
      failed: () => 'Trusted proxy is set to trust all — IP spoofing via X-Forwarded-For is possible',
    });
  },
});
