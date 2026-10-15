import { defineCheck } from '../../core/check-builder.js';
import { hermesApiServer } from '../../adapters/hermes-api-server.js';
import { CODING_AGENTS, type Evidence, type FixResult } from '../../core/types.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';
import { envOverridesOf } from '../../adapters/env-overrides.js';

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

const HOST_PATHS = ['gateway.host', 'server.host', 'host', 'GATEWAY_HOST'];
const WILDCARD_ADDRS = ['0.0.0.0', '[::]', '::'];
/** Bind values that expose the listener beyond loopback (symbolic modes and wildcard addresses). */
const SYMBOLIC_EXPOSED = ['all', 'lan', 'auto', ...WILDCARD_ADDRS];

/**
 * Why an exposed symbolic bind is reported. OpenClaw 2026.9.4 `gateway.bind`:
 * "lan" listens on 0.0.0.0; "auto" prefers the tailnet address, then LAN
 * (0.0.0.0, also the container default) — its schema: '"auto" can expose all
 * interfaces' (docs.openclaw.ai/gateway/config-gateway).
 */
function bindDetail(bind: string): string {
  switch (bind.toLowerCase()) {
    case 'lan': return 'Gateway bind mode "lan" — listens on 0.0.0.0, accessible from all network interfaces';
    case 'auto': return 'Gateway bind mode "auto" — picks the tailnet address, else LAN (0.0.0.0, every interface); "loopback" keeps it local';
    default: return `Gateway bind mode "${bind}" — accessible from all network interfaces`;
  }
}

/** OpenClaw: Tailscale serve/funnel forces the gateway onto loopback, whatever gateway.bind says. */
function tailscaleForcesLoopback(data: Record<string, unknown>): boolean {
  const mode = getNestedValue(data, 'gateway.tailscale.mode');
  return mode === 'serve' || mode === 'funnel';
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
    // Hermes' API server is bearer-authenticated once a key is set; exposure
    // without one is HM-004's critical finding, not a second one here.
    if (ctx.installation.agent === 'hermes' && hermesApiServer(ctx.configs).key) {
      return h.passed(`Hermes API server listens on ${ctx.installation.gateway?.host ?? 'its configured host'} with an API key (HM-004 covers unauthenticated exposure)`);
    }
    const evidence: Evidence[] = [];
    // The fix rewrites gateway.host / GATEWAY_HOST; only offer it when that
    // key is what is exposed (a channel webhook needs its own setting).
    let gatewayKey = false;

    for (const config of ctx.configs) {
      // OpenClaw in remote mode connects to a gateway elsewhere; its local
      // bind settings configure no listener
      if (ctx.installation.agent === 'openclaw' && getNestedValue(config.data, 'gateway.mode') === 'remote') continue;
      // The first host key present is the gateway's; the walk below skips
      // only that one (and a flagged bind), so a second wildcard listener
      // such as server.host is still reported.
      const hostPath = HOST_PATHS.find(p => getNestedValue(config.data, p) != null);
      const host = hostPath ? getNestedValue(config.data, hostPath) : undefined;
      const reported = new Set<string>(hostPath ? [hostPath] : []);

      const WILDCARD_BINDS = ['0.0.0.0', '[::]', '::'];

      // A host may be a comma-separated list, and `*` means every interface
      // (PicoClaw's gateway.host accepts both).
      const hostParts = typeof host === 'string' ? host.split(',').map(p => p.trim()) : [];
      if (hostParts.some(p => p === '*' || WILDCARD_BINDS.includes(p))) {
        // Set by an env override (ZeroClaw's ZEROCLAW_GATEWAY_HOST…): the
        // file doesn't hold it, so there is nothing for a fix to rewrite
        const env = envOverridesOf(config.data).find(o => o.path === hostPath)?.env;
        if (!env) gatewayKey = true;
        evidence.push({
          file: config.filePath,
          detail: env
            ? `Gateway bound to ${host} by the ${env} environment variable — accessible from all network interfaces`
            : `Gateway bound to ${host} — accessible from all network interfaces`,
        });
      }

      // Symbolic bind modes (OpenClaw 2026.x schema: gateway.bind = "loopback" | "lan" | "all")
      const bind = getNestedValue(config.data, 'gateway.bind') ?? getNestedValue(config.data, 'bind');
      if (getNestedValue(config.data, 'gateway.bind') !== undefined) reported.add('gateway.bind');
      else if (getNestedValue(config.data, 'bind') !== undefined) reported.add('bind');
      if (typeof bind === 'string' && SYMBOLIC_EXPOSED.includes(bind.toLowerCase())
          && !tailscaleForcesLoopback(config.data)) {
        gatewayKey = true;
        evidence.push({ file: config.filePath, detail: bindDetail(bind) });
      }

      // Any other listener bound to a wildcard address (channel webhooks,
      // web UIs, ENV-style HTTP_HOST=…). Walk the parsed config so disabled
      // sections — framework config templates ship every channel with
      // `enabled: false` and a 0.0.0.0 placeholder — are not reported.
      if (config.data && Object.keys(config.data).length > 0) {
        const lines = config.raw.split('\n');
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

    // The listener the adapter resolved (NET-001's view) can come from keys
    // this walk can't read as a bind: PicoClaw's launcher `public: true`,
    // OpenShell's `bind_address = "0.0.0.0:8080"`, an env override.
    const gw = ctx.installation.gateway;
    if (evidence.length === 0 && gw?.host && WILDCARD_ADDRS.includes(gw.host.trim())) {
      evidence.push({
        file: ctx.installation.configFiles[0]?.filePath ?? ctx.installation.installDir,
        detail: `Gateway listener resolves to ${gw.host}${gw.port ? `:${gw.port}` : ''} — accessible from all network interfaces`,
      });
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
      fixDescription: 'Rebind the gateway to loopback (127.0.0.1, or gateway.bind "loopback")',
    });
  },

  // Rewrite the key that is exposed, in the file it is in. OpenClaw 2026.x
  // has no gateway.host (its schema rejects unknown keys): its listener is
  // the symbolic gateway.bind, whose local-only value is "loopback".
  // Every exposed file is rewritten (openclaw.json and a sub-agent's file,
  // a JSON config and its .env), so one run leaves no listener behind.
  async fix(ctx) {
    const done: string[] = [];
    for (const config of ctx.configs) {
      let result: FixResult | undefined;
      const symbolic = ['gateway.bind', 'bind'].find(path => {
        const bind = getNestedValue(config.data, path);
        return typeof bind === 'string' && SYMBOLIC_EXPOSED.includes(bind.toLowerCase())
          && !tailscaleForcesLoopback(config.data);
      });
      if (symbolic) {
        result = await fixFirstConfig([config], {
          checkId: 'CFG-001', path: symbolic, value: 'loopback', message: `Set ${symbolic} to "loopback"`,
        });
      } else {
        const hostPath = HOST_PATHS.find(p => getNestedValue(config.data, p) != null);
        const host = hostPath ? getNestedValue(config.data, hostPath) : undefined;
        const fromEnv = envOverridesOf(config.data).some(o => o.path === hostPath);
        if (!fromEnv && typeof host === 'string' && host.split(',').some(p => p.trim() === '*' || WILDCARD_ADDRS.includes(p.trim()))) {
          result = await fixFirstConfig([config], {
            checkId: 'CFG-001',
            env: hostPath === 'GATEWAY_HOST' ? 'GATEWAY_HOST' : undefined,
            path: hostPath === 'GATEWAY_HOST' ? undefined : hostPath,
            value: '127.0.0.1',
            message: `Set ${hostPath} to 127.0.0.1`,
          });
        }
      }
      if (result?.applied) done.push(`${result.message} in ${config.filePath}`);
    }
    return done.length > 0
      ? { checkId: 'CFG-001', applied: true, message: done.join('; ') }
      : { checkId: 'CFG-001', applied: false, message: 'No wildcard gateway listener found to rebind' };
  },
});
