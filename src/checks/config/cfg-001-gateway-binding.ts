import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS, type Evidence } from '../../core/types.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

const LISTENER_KEY = /host|bind|listen/i;

interface ListenerHit { path: string; key: string; value: string }

/** Wildcard-bound listener keys in a parsed config, skipping disabled sections. */
function wildcardListeners(data: unknown, wildcards: string[], path = '', depth = 0): ListenerHit[] {
  if (depth > 8 || !data || typeof data !== 'object' || Array.isArray(data)) return [];
  const obj = data as Record<string, unknown>;
  if (obj.enabled === false || obj.enable === false) return [];
  const hits: ListenerHit[] = [];
  for (const [key, value] of Object.entries(obj)) {
    const p = path ? `${path}.${key}` : key;
    if (typeof value === 'string' && LISTENER_KEY.test(key) && wildcards.includes(value.trim())) {
      hits.push({ path: p, key, value: value.trim() });
    } else if (value && typeof value === 'object') {
      hits.push(...wildcardListeners(value, wildcards, p, depth + 1));
    }
  }
  return hits;
}

export const cfg001 = defineCheck({
  id: 'CFG-001',
  name: 'Gateway Binding',
  category: 'config',
  severity: 'critical',
  description: 'Check if gateway is bound to 0.0.0.0 (all interfaces), exposing it to the network',
  // Lyrie's only listener setting is LYRIE_WEBCHAT_HOST, which nothing binds
  // in 3.4.0; LY-010 reports it with the right context. IronClaw's listeners
  // are IC-001's (its schemas have no gateway.host for this fix to write).
  excludedAgents: [...CODING_AGENTS, 'lyrie', 'ironclaw'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    // The fix rewrites gateway.host / GATEWAY_HOST; only offer it when that
    // key is what is exposed (a channel webhook needs its own setting).
    let gatewayKey = false;

    for (const config of ctx.configs) {
      const host =
        getNestedValue(config.data, 'gateway.host') ??
        getNestedValue(config.data, 'server.host') ??
        getNestedValue(config.data, 'host') ??
        config.data.GATEWAY_HOST;

      const WILDCARD_BINDS = ['0.0.0.0', '[::]', '::'];

      // A host may be a comma-separated list, and `*` means every interface
      // (PicoClaw's gateway.host accepts both).
      const hostParts = typeof host === 'string' ? host.split(',').map(p => p.trim()) : [];
      if (hostParts.some(p => p === '*' || WILDCARD_BINDS.includes(p))) {
        gatewayKey = true;
        evidence.push({
          file: config.filePath,
          detail: `Gateway bound to ${host} — accessible from all network interfaces`,
        });
      }

      // Symbolic bind modes (OpenClaw 2026.x schema: gateway.bind = "loopback" | "lan" | "all")
      const bind = getNestedValue(config.data, 'gateway.bind') ?? getNestedValue(config.data, 'bind');
      if (typeof bind === 'string' && ['all', 'lan', ...WILDCARD_BINDS].includes(bind.toLowerCase())) {
        gatewayKey = true;
        evidence.push({
          file: config.filePath,
          detail: bind.toLowerCase() === 'lan'
            ? 'Gateway bind mode "lan" — accessible from the local network'
            : `Gateway bind mode "${bind}" — accessible from all network interfaces`,
        });
      }

      // Any other listener bound to a wildcard address (channel webhooks,
      // web UIs, ENV-style HTTP_HOST=…). Walk the parsed config so disabled
      // sections — framework config templates ship every channel with
      // `enabled: false` and a 0.0.0.0 placeholder — are not reported.
      if (config.data && Object.keys(config.data).length > 0) {
        const lines = config.raw.split('\n');
        const reported = new Set(['gateway.host', 'server.host', 'host', 'GATEWAY_HOST', 'gateway.bind', 'bind']);
        for (const hit of wildcardListeners(config.data, WILDCARD_BINDS)) {
          if (reported.has(hit.path)) continue;
          const line = lines.findIndex(l => l.includes(hit.key) && l.includes(hit.value));
          evidence.push({
            file: config.filePath,
            ...(line >= 0 ? { line: line + 1, snippet: lines[line].trim() } : {}),
            detail: `${hit.path} = ${hit.value} — listener accessible from all network interfaces`,
          });
        }
      } else if (WILDCARD_BINDS.some(w => config.raw.includes(w))) {
        // Unparsed content: fall back to grep-style detection.
        const lines = config.raw.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const hasMatch = WILDCARD_BINDS.some(w => lines[i].includes(w));
          if (hasMatch && LISTENER_KEY.test(lines[i])) {
            evidence.push({
              file: config.filePath,
              line: i + 1,
              snippet: lines[i].trim(),
            });
          }
        }
      }
    }

    // Deduplicate by file
    const uniqueEvidence = evidence.filter((e, i, arr) =>
      arr.findIndex(x => x.file === e.file && (e.line !== undefined ? x.line === e.line : x.detail === e.detail)) === i
    );

    return h.result({
      passed: uniqueEvidence.length === 0,
      message: uniqueEvidence.length === 0
        ? 'Gateway is not bound to 0.0.0.0'
        : 'Gateway is bound to 0.0.0.0 — accessible from all network interfaces',
      evidence: uniqueEvidence,
      fixable: gatewayKey,
      fixDescription: 'Rebind gateway to 127.0.0.1',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: 'CFG-001',
      env: 'GATEWAY_HOST',
      path: 'gateway.host',
      value: '127.0.0.1',
      message: 'Set gateway host to 127.0.0.1',
      noConfigMessage: 'No config file found',
    });
  },
});
