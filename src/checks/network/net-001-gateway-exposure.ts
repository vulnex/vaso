import { defineCheck } from '../../core/check-builder.js';
import { hermesApiServer } from '../../adapters/hermes-api-server.js';
import { CODING_AGENTS } from '../../core/types.js';

export const net001 = defineCheck({
  id: 'NET-001',
  name: 'Gateway Internet Exposure',
  category: 'network',
  severity: 'critical',
  description: 'Check if the gateway is bound to a public address',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    const gw = ctx.installation.gateway;
    if (!gw?.host) return h.passed('No gateway configured');
    // Hermes' API server takes a bearer key; unauthenticated exposure is
    // HM-004's critical finding (CFG-001 defers the same way)
    if (ctx.installation.agent === 'hermes' && hermesApiServer(ctx.configs).key) {
      return h.passed(`Hermes API server on ${gw.host}:${gw.port ?? '?'} requires an API key (HM-004 covers unauthenticated exposure)`);
    }

    const publicBind = gw.host === '0.0.0.0' || gw.host === '::';
    return h.result({
      passed: !publicBind,
      message: publicBind
        ? `Gateway bound to ${gw.host}:${gw.port ?? '?'} — exposed to all network interfaces`
        : `Gateway bound to ${gw.host} — not publicly exposed`,
    });
  },
});
