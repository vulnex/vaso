import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

const LOOPBACK_HOST = /^(?:localhost|127(?:\.\d{1,3}){3}|\[?::1\]?)$/i;
const TLS_KEY = /^(?:tls|ssl|https)$|(?:^|_)(?:TLS|SSL|HTTPS)(?:_ENABLED?)?$/i;

/** A host value (PicoClaw accepts a comma list) that only names loopback addresses. */
function loopbackOnly(host: string): boolean {
  const parts = host.split(',').map(p => p.trim()).filter(Boolean);
  return parts.length > 0 && parts.every(p => LOOPBACK_HOST.test(p));
}

function isOn(v: unknown): boolean {
  return v === true || (typeof v === 'string' && /^(?:true|1|on|yes)$/i.test(v.trim()));
}

/**
 * TLS switched on somewhere in a parsed config: a `tls`/`ssl` flag that is
 * true, or such a section whose `enabled` is true. Reading values (not the
 * raw text) keeps `{"tls":{"enabled":false,"autoGenerate":true}}` — TLS off,
 * on one line — from passing.
 */
function tlsEnabled(data: unknown, depth = 0): boolean {
  if (depth > 8 || !data || typeof data !== 'object' || Array.isArray(data)) return false;
  for (const [key, value] of Object.entries(data as Record<string, unknown>)) {
    if (TLS_KEY.test(key)) {
      if (isOn(value)) return true;
      if (value && typeof value === 'object' && !Array.isArray(value) && isOn((value as Record<string, unknown>).enabled)) return true;
    }
    if (value && typeof value === 'object' && tlsEnabled(value, depth + 1)) return true;
  }
  return false;
}

export const cfg004 = defineCheck({
  id: 'CFG-004',
  name: 'TLS Not Configured',
  category: 'config',
  severity: 'warning',
  description: 'Check if TLS/HTTPS is configured for the gateway',
  // OpenShell: OSH-001 reports disable_tls with the listener context
  excludedAgents: [...CODING_AGENTS, 'openshell'],

  async run(ctx, h) {
    if (!ctx.installation.gateway) {
      return h.passed('No gateway configured — TLS check not applicable');
    }

    const gw = ctx.installation.gateway;
    // TLS protects traffic crossing a network; a loopback-only listener
    // never does.
    if (gw.host && loopbackOnly(gw.host)) {
      return h.passed(`Gateway is bound to loopback (${gw.host}) — TLS not required`);
    }
    // OpenClaw 2026.x: a tailnet bind is reachable only over Tailscale's
    // WireGuard tunnel, and serve/funnel put the gateway on loopback behind
    // Tailscale's HTTPS (docs.openclaw.ai/gateway/config-gateway).
    if (ctx.installation.agent === 'openclaw') {
      for (const config of ctx.configs) {
        const tailscale = getNestedValue(config.data, 'gateway.tailscale.mode');
        if (tailscale === 'serve' || tailscale === 'funnel') {
          return h.passed(`Gateway is published through Tailscale ${tailscale} (HTTPS terminated by Tailscale)`);
        }
        if (getNestedValue(config.data, 'gateway.bind') === 'tailnet') {
          return h.passed('Gateway binds to the tailnet address — traffic is encrypted by Tailscale (WireGuard)');
        }
      }
    }
    const hasTls = gw.tls === true;

    let tlsInConfig = false;
    for (const config of ctx.configs) {
      const parsed = config.data && Object.keys(config.data).length > 0;
      if (parsed ? tlsEnabled(config.data) : /\b(?:tls|ssl)\b.*:\s*true/i.test(config.raw)) {
        tlsInConfig = true;
      }
    }

    // The adapter's merged view wins when it knows: a sub-agent config that
    // turns TLS off overrides the global file that turned it on.
    const passed = typeof gw.tls === 'boolean' ? gw.tls : hasTls || tlsInConfig;

    return h.result({
      passed,
      message: passed
        ? 'TLS is configured for the gateway'
        : 'TLS is not configured — traffic is unencrypted',
    });
  },
});
