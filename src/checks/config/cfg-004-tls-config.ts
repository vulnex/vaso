import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';
import { isOpenclawAutoBind } from '../../adapters/openclaw-bind.js';
import { isLoopbackAddress } from '../../core/listen-address.js';

const TLS_KEY = /^(?:tls|ssl|https)$|(?:^|_)(?:TLS|SSL|HTTPS)(?:_ENABLED?)?$/i;

/** A host value (PicoClaw accepts a comma list) that only names loopback addresses. */
function loopbackOnly(host: string): boolean {
  const parts = host.split(',').map(p => p.trim()).filter(Boolean);
  return parts.length > 0 && parts.every(p => isLoopbackAddress(p));
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

/**
 * OpenClaw `gateway.mode: "remote"` (a client of another host's gateway):
 * undefined when not in remote mode, null when the link is encrypted
 * (wss://, an SSH tunnel, or a loopback URL), else the plaintext ws:// URL.
 */
function openclawRemotePlaintext(configs: { data: Record<string, unknown> }[]): string | null | undefined {
  const config = configs.find(c => getNestedValue(c.data, 'gateway.mode') === 'remote');
  if (!config) return undefined;
  if (getNestedValue(config.data, 'gateway.remote.transport') === 'ssh') return null;
  const url = getNestedValue(config.data, 'gateway.remote.url');
  if (typeof url !== 'string' || !/^ws:\/\//i.test(url.trim())) return null;
  let host: string;
  try {
    host = new URL(url.trim()).hostname;
  } catch {
    return null;
  }
  return loopbackOnly(host) ? null : url.trim();
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
    if (ctx.installation.agent === 'openclaw') {
      const remote = openclawRemotePlaintext(ctx.configs);
      if (remote !== undefined) {
        const file = ctx.configs.find(c => getNestedValue(c.data, 'gateway.mode') === 'remote')?.filePath;
        return h.result({
          passed: remote === null,
          message: remote === null
            ? 'Remote gateway mode — no local listener; the link to the remote gateway is encrypted (wss:// or SSH)'
            : `Remote gateway mode connects over plaintext ${remote} — the gateway token and traffic travel unencrypted`,
          evidence: remote === null || !file ? [] : [{ file, detail: `gateway.remote.url = ${remote}` }],
        });
      }
    }
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
        // "auto" the adapter couldn't resolve (a snapshot can't tell whether
        // the host is a container): loopback unless containerised — CFG-001
        // reports that caveat
        if (!gw.host && isOpenclawAutoBind(getNestedValue(config.data, 'gateway.bind'))) {
          return h.passed('Gateway bind mode "auto" listens on loopback outside containers — TLS not required there (CFG-001 notes the container case)');
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
