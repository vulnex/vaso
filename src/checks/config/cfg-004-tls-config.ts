import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';

export const cfg004 = defineCheck({
  id: 'CFG-004',
  name: 'TLS Not Configured',
  category: 'config',
  severity: 'warning',
  description: 'Check if TLS/HTTPS is configured for the gateway',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    if (!ctx.installation.gateway) {
      return h.passed('No gateway configured — TLS check not applicable');
    }

    const gw = ctx.installation.gateway;
    const hasTls = gw.tls === true;

    // Also check raw config for tls/ssl mentions
    let tlsInConfig = false;
    for (const config of ctx.configs) {
      if (/\btls\b.*:\s*true/i.test(config.raw) || /\bssl\b.*:\s*true/i.test(config.raw)) {
        tlsInConfig = true;
      }
    }

    const passed = hasTls || tlsInConfig;

    return h.result({
      passed,
      message: passed
        ? 'TLS is configured for the gateway'
        : 'TLS is not configured — traffic is unencrypted',
    });
  },
});
