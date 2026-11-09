import { defineCheck } from '../../core/check-builder.js';
import { hermesApiServer, hermesApiServerState } from '../../adapters/hermes-api-server.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

/** Addresses meaning "every interface" (IPv4, IPv6 with or without brackets, `*`). */
const WILDCARD_HOSTS = new Set(['0.0.0.0', '::', '[::]', '*']);

export const net001 = defineCheck({
  id: 'NET-001',
  name: 'Gateway Internet Exposure',
  category: 'network',
  severity: 'critical',
  description: 'Check if the gateway is bound to a public address',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    const gw = ctx.installation.gateway;
    // An OpenClaw gateway whose address depends on the host ("auto" on a
    // snapshot without the container markers, "tailnet") is configured
    if (gw && !gw.host && ctx.installation.agent === 'openclaw') {
      return h.passed('Gateway configured, but its listen address can\'t be determined here (CFG-001 reports the bind mode)');
    }
    if (!gw?.host) return h.passed('No gateway configured');
    // Hermes' API server takes a bearer key, and releases with the start-up
    // guard refuse to run it without one; HM-004 reports the
    // release-dependent case (CFG-001 defers the same way)
    if (ctx.installation.agent === 'hermes'
        && hermesApiServerState(hermesApiServer(ctx.configs, ctx.installation.version), ctx.installation.version) !== 'unauthenticated') {
      return h.passed(`Hermes API server on ${gw.host}:${gw.port ?? '?'} requires an API key or is refused without one (HM-004 covers unauthenticated exposure)`);
    }

    // OpenClaw Tailscale Funnel publishes the (loopback-bound) gateway on the
    // public internet; OpenClaw then requires password auth, so it is
    // reachable but not open
    if (ctx.installation.agent === 'openclaw') {
      const funnel = ctx.configs.find(c => getNestedValue(c.data, 'gateway.tailscale.mode') === 'funnel');
      if (funnel) {
        return h.result({
          passed: false,
          severity: 'warning',
          message: 'Gateway published to the public internet through Tailscale Funnel (password auth required) — use "serve" for tailnet-only access',
          evidence: [{ file: funnel.filePath, detail: 'gateway.tailscale.mode = funnel' }],
        });
      }
    }

    const host = gw.host.trim();
    const publicBind = WILDCARD_HOSTS.has(host) || host.split(',').some(p => WILDCARD_HOSTS.has(p.trim()));
    return h.result({
      passed: !publicBind,
      message: publicBind
        ? `Gateway bound to ${gw.host}:${gw.port ?? '?'} — exposed to all network interfaces`
        : `Gateway bound to ${gw.host} — not publicly exposed`,
    });
  },
});
