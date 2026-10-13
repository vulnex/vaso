import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

/** A trusted-proxy entry that matches every client. */
const ANY_ADDRESS = /^(?:\*|0\.0\.0\.0\/0|::\/0|0\.0\.0\.0)$/;

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

      // OpenClaw 2026.x: gateway.trustedProxies is a list of addresses/CIDRs
      const proxies = getNestedValue(config.data, 'gateway.trustedProxies');
      if (Array.isArray(proxies)) {
        const any = proxies.filter(p => typeof p === 'string' && ANY_ADDRESS.test(p.trim()));
        if (any.length > 0) {
          evidence.push({ file: config.filePath, detail: `gateway.trustedProxies: ${any.join(', ')} — every address is a trusted proxy` });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No unrestricted proxy trust detected',
      failed: () => 'Trusted proxy is set to trust all — IP spoofing via X-Forwarded-For is possible',
    });
  },
});
