import { defineCheck } from '../../core/check-builder.js';
import { hermesApiServer, hermesApiServerState, HERMES_API_DISABLED } from '../../adapters/hermes-api-server.js';
import { CODING_AGENTS, type Evidence, type FixResult } from '../../core/types.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';
import { envOverridesOf } from '../../adapters/env-overrides.js';
import { managedOverride } from '../../adapters/hermes-managed.js';
import { containerEnvironment, isOpenclawAutoBind, openclawAutoBindDetail } from '../../adapters/openclaw-bind.js';
import { hostPort, isWildcardAddress } from '../../core/listen-address.js';
import { picoclawPublicLauncher } from '../../adapters/picoclaw.js';

const LISTENER_KEY = /host|bind|listen/i;

interface ListenerHit { path: string; key: string; value: string }

/** Whether a listener value (at a config path) binds every interface. */
type WildcardTest = (value: string, path: string) => boolean;

/**
 * Any wildcard spelling (src/core/listen-address.ts). Nanobot's websocket
 * channel hands its host to asyncio, which binds every interface for an
 * empty one (pydantic keeps "").
 */
function listenerTest(agent: string): WildcardTest {
  return (value, path) => {
    // A bare `0` is an address only under a key that names one
    // (`host`, `bind_host`, `listenAddress`), not `hostKeyChecking: "0"`
    if (/^\s*0+\s*$/.test(value) && !/(?:host|bind|listen|addr|address)$/i.test(path.split('.').pop() ?? '')) return false;
    return isWildcardAddress(value, {
      emptyIsWildcard: agent === 'nanobot' && /^channels\.websocket\.host$/i.test(path),
    });
  };
}

/** Wildcard-bound listener keys in a parsed config, skipping disabled sections. */
function wildcardListeners(data: unknown, isWildcard: WildcardTest, path = '', depth = 0): ListenerHit[] {
  if (depth > 8 || !data || typeof data !== 'object' || Array.isArray(data)) return [];
  const obj = data as Record<string, unknown>;
  if (obj.enabled === false || obj.enable === false) return [];
  const hits: ListenerHit[] = [];
  for (const [key, value] of Object.entries(obj)) {
    const p = path ? `${path}.${key}` : key;
    if (typeof value === 'string' && LISTENER_KEY.test(key) && isWildcard(value, p)) {
      hits.push({ path: p, key, value: value.trim() === '' ? '""' : value.trim() });
    } else if (value && typeof value === 'object') {
      hits.push(...wildcardListeners(value, isWildcard, p, depth + 1));
    }
  }
  return hits;
}

/** Nanobot's websocket channel served on a unix socket instead of TCP (runtime.py runner). */
function nanobotUnixSocket(data: Record<string, unknown>): boolean {
  const ws = getNestedValue(data, 'channels.websocket');
  if (!ws || typeof ws !== 'object') return false;
  const path = (ws as Record<string, unknown>).unixSocketPath ?? (ws as Record<string, unknown>).unix_socket_path;
  return typeof path === 'string' && path.trim().length > 0;
}

/** The wildcard address the evidence names (`::` binds IPv6 too), for the headline. */
function wildcardLabel(evidence: Evidence[]): string {
  const text = evidence.map(e => e.detail ?? '').join(' ');
  const ipv6 = /(?:^|[\s=])(?:\[::\]|::)(?=[\s:—]|$)/.test(text)
    || text.split(/\s+/).some(t => t.includes(':') && isWildcardAddress(t.replace(/^(\[[^\]]*\]):\d+$/, '$1')));
  if (ipv6 && !text.includes('0.0.0.0')) return '::';
  return '0.0.0.0';
}

const HOST_PATHS = ['gateway.host', 'server.host', 'host', 'GATEWAY_HOST'];
/** Symbolic bind values that expose the listener beyond loopback (wildcard addresses also do). */
const SYMBOLIC_EXPOSED = ['all', 'lan', 'auto'];
/** A bind value that exposes the listener: a symbolic mode or any wildcard spelling. */
function exposedBind(bind: string): boolean {
  return SYMBOLIC_EXPOSED.includes(bind.trim().toLowerCase()) || (bind.trim() !== '' && isWildcardAddress(bind));
}
/** Raw-text fallback for configs that didn't parse: the common spellings only. */
const WILDCARD_TEXT = ['0.0.0.0', '[::]', '::'];

/**
 * Why an exposed symbolic bind is reported. OpenClaw `gateway.bind` "lan"
 * listens on 0.0.0.0; its "auto" depends on whether the gateway runs in a
 * container (src/adapters/openclaw-bind.ts).
 */
function bindDetail(bind: string): string {
  switch (bind.toLowerCase()) {
    case 'lan': return 'Gateway bind mode "lan" — listens on 0.0.0.0, accessible from all network interfaces';
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
    // Hermes' API server is bearer-authenticated once a key is set, and
    // releases with the start-up guard refuse to run it without one; only a
    // server that starts unauthenticated is exposure for this check (HM-004
    // reports the release-dependent case).
    if (ctx.installation.agent === 'hermes') {
      const state = hermesApiServerState(hermesApiServer(ctx.configs, ctx.installation.version), ctx.installation.version);
      if (state === 'disabled') return h.passed(HERMES_API_DISABLED);
      if (state !== 'unauthenticated') {
        return h.passed(state === 'refused'
          ? `Hermes ${ctx.installation.version} refuses to start the API server without a usable API_SERVER_KEY`
          : `Hermes API server listens on ${ctx.installation.gateway?.host ?? 'its configured host'} with an API key or behind the start-up key guard (HM-004 covers unauthenticated exposure)`);
      }
    }
    const evidence: Evidence[] = [];
    // The wildcard addresses as configured, for a headline that matches NET-001's
    const spellings = new Set<string>();
    // The fix rewrites gateway.host / GATEWAY_HOST; only offer it when that
    // key is what is exposed (a channel webhook needs its own setting).
    let gatewayKey = false;
    // OpenClaw "auto" is 0.0.0.0 only inside a container
    const inContainer = ctx.installation.agent === 'openclaw' ? await containerEnvironment(ctx.fs) : undefined;

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

      // A host may be a comma-separated list, and `*` means every interface
      // (PicoClaw's gateway.host accepts both).
      const hostParts = typeof host === 'string' ? host.split(',').map(p => p.trim()) : [];
      if (hostParts.some(p => p !== '' && isWildcardAddress(p))) {
        // Set by an env override (ZeroClaw's ZEROCLAW_GATEWAY_HOST…): the
        // file doesn't hold it, so there is nothing for a fix to rewrite
        const env = envOverridesOf(config.data).find(o => o.path === hostPath)?.env;
        if (ctx.installation.agent === 'nanobot' && hostPath === 'gateway.host') {
          // Nanobot's gateway.host serves only GET /health (readiness and
          // runtime identity); the agent is reached over the websocket
          // channel, whose own host the walk below reports
          evidence.push({
            file: config.filePath,
            detail: `gateway.host = ${host} — nanobot's health endpoint (GET /health only) on every interface; the agent itself is reached through channels.websocket`,
            mitigated: true,
          });
        } else {
          if (!env) gatewayKey = true;
          for (const p of hostParts) if (p !== '' && isWildcardAddress(p)) spellings.add(p);
          evidence.push({
            file: config.filePath,
            detail: env
              ? `Gateway bound to ${host} by the ${env} environment variable — accessible from all network interfaces`
              : `Gateway bound to ${host} — accessible from all network interfaces`,
          });
        }
      }

      // Symbolic bind modes (OpenClaw 2026.x schema: gateway.bind = "loopback" | "lan" | "all")
      const bind = getNestedValue(config.data, 'gateway.bind') ?? getNestedValue(config.data, 'bind');
      if (getNestedValue(config.data, 'gateway.bind') !== undefined) reported.add('gateway.bind');
      else if (getNestedValue(config.data, 'bind') !== undefined) reported.add('bind');
      if (typeof bind === 'string' && exposedBind(bind)
          && !tailscaleForcesLoopback(config.data)) {
        if (ctx.installation.agent === 'openclaw' && isOpenclawAutoBind(bind)) {
          // Outside a container (or unknowable, on a snapshot) it is a
          // caveat, not an exposure: reported as information
          if (inContainer) gatewayKey = true;
          evidence.push({ file: config.filePath, detail: openclawAutoBindDetail(inContainer), ...(inContainer ? {} : { mitigated: true }) });
        } else {
          gatewayKey = true;
          evidence.push({ file: config.filePath, detail: bindDetail(bind) });
        }
      }

      // Any other listener bound to a wildcard address (channel webhooks,
      // web UIs, ENV-style HTTP_HOST=…). Walk the parsed config so disabled
      // sections — framework config templates ship every channel with
      // `enabled: false` and a 0.0.0.0 placeholder — are not reported.
      if (config.data && Object.keys(config.data).length > 0) {
        const lines = config.raw.split('\n');
        for (const hit of wildcardListeners(config.data, listenerTest(ctx.installation.agent))) {
          if (reported.has(hit.path)) continue;
          // Hermes: a value its administrator-managed layer replaces binds nothing
          if (managedOverride(ctx.configs, config, hit.path)) continue;
          // Nanobot: channels.websocket.unixSocketPath replaces the TCP listener
          if (ctx.installation.agent === 'nanobot' && /^channels\.websocket\.host$/i.test(hit.path)
              && nanobotUnixSocket(config.data)) continue;
          const line = lines.findIndex(l => l.includes(hit.key) && l.includes(hit.value));
          evidence.push({
            file: config.filePath,
            ...(line >= 0 ? { line: line + 1, snippet: lines[line].trim() } : {}),
            detail: `${hit.path} = ${hit.value} — listener accessible from all network interfaces`,
          });
          spellings.add(hit.value);
        }
      } else if (WILDCARD_TEXT.some(w => config.raw.includes(w))) {
        // Unparsed content: fall back to grep-style detection.
        const lines = config.raw.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const hasMatch = WILDCARD_TEXT.some(w => lines[i].includes(w));
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

    // PicoClaw: a public launcher puts the gateway on every interface over
    // gateway.host, so the finding is the launcher's and no config.json
    // rewrite would clear it
    const launcher = ctx.installation.agent === 'picoclaw' ? picoclawPublicLauncher(ctx.configs) : undefined;
    if (launcher) {
      gatewayKey = false;
      const line = launcher.raw.split('\n').findIndex(l => /"public"\s*:\s*true/.test(l));
      evidence.push({
        file: launcher.filePath,
        ...(line >= 0 ? { line: line + 1, snippet: launcher.raw.split('\n')[line].trim() } : {}),
        detail: `public: true — the PicoClaw launcher starts the gateway on all interfaces (0.0.0.0:${ctx.installation.gateway?.port ?? 18790}), whatever gateway.host says`,
      });
    }

    // The listener the adapter resolved (NET-001's view) can come from keys
    // this walk can't read as a bind: PicoClaw's launcher `public: true`,
    // OpenShell's `bind_address = "0.0.0.0:8080"`, an env override.
    const gw = ctx.installation.gateway;
    if (evidence.length === 0 && gw?.host && gw.host.split(',').some(p => p.trim() !== '' && isWildcardAddress(p))) {
      spellings.add(gw.host);
      evidence.push({
        file: ctx.installation.configFiles[0]?.filePath ?? ctx.installation.installDir,
        detail: `Gateway listener resolves to ${hostPort(gw.host, gw.port || undefined)} — accessible from all network interfaces`,
      });
    }

    // Deduplicate by file
    const uniqueEvidence = evidence.filter((e, i, arr) =>
      arr.findIndex(x => x.file === e.file && (e.line !== undefined ? x.line === e.line : x.detail === e.detail)) === i
    );

    // Only OpenClaw "auto" outside a known container, or nanobot's health
    // endpoint: informational
    const allMitigated = uniqueEvidence.length > 0 && uniqueEvidence.every(e => e.mitigated);
    return h.result({
      passed: uniqueEvidence.length === 0,
      ...(allMitigated ? { severity: 'info' as const } : {}),
      message: uniqueEvidence.length === 0
        ? 'Gateway is not bound to 0.0.0.0'
        : allMitigated
          ? ctx.installation.agent === 'nanobot'
            ? 'Nanobot health endpoint listens on all interfaces (GET /health only; no agent access)'
            : 'Gateway bind mode "auto" listens on 0.0.0.0 (all interfaces) when the gateway runs in a container'
          : `Gateway is bound to ${spellings.size === 1 ? [...spellings][0] : wildcardLabel(uniqueEvidence)} — accessible from all network interfaces`,
      evidence: uniqueEvidence,
      fixable: gatewayKey,
      fixDescription: 'Rebind the gateway to loopback (127.0.0.1, or gateway.bind "loopback")',
    });
  },

  // Rewrite the key that is exposed, in the file it is in. OpenClaw 2026.x
  // has no gateway.host (its schema rejects unknown keys): its listener is
  // the symbolic gateway.bind, whose local-only value is "loopback".
  // Every exposed file is rewritten (openclaw.json and a sub-agent's file,
  // a JSON config and its .env), so one run leaves no gateway listener
  // behind. Other wildcard listeners (a channel's own server) are named in
  // the result, not rewritten: they need their own setting.
  async fix(ctx) {
    const done: string[] = [];
    const remaining: string[] = [];
    const inContainer = ctx.installation.agent === 'openclaw' ? await containerEnvironment(ctx.fs) : undefined;
    for (const config of ctx.configs) {
      let result: FixResult | undefined;
      const rewritten = new Set<string>();
      const symbolic = ['gateway.bind', 'bind'].find(path => {
        const bind = getNestedValue(config.data, path);
        return typeof bind === 'string' && exposedBind(bind)
          && !tailscaleForcesLoopback(config.data)
          // OpenClaw "auto" exposes nothing outside a container
          && !(ctx.installation.agent === 'openclaw' && isOpenclawAutoBind(bind) && !inContainer);
      });
      if (symbolic) {
        rewritten.add(symbolic);
        result = await fixFirstConfig([config], {
          checkId: 'CFG-001', path: symbolic, value: 'loopback', message: `Set ${symbolic} to "loopback"`,
        });
      } else {
        const hostPath = HOST_PATHS.find(p => getNestedValue(config.data, p) != null);
        const host = hostPath ? getNestedValue(config.data, hostPath) : undefined;
        const fromEnv = envOverridesOf(config.data).some(o => o.path === hostPath);
        // PicoClaw's public launcher overrides gateway.host: rewriting it clears nothing
        const overridden = ctx.installation.agent === 'picoclaw' && !!picoclawPublicLauncher(ctx.configs);
        if (!fromEnv && !overridden && typeof host === 'string' && host.split(',').some(p => p.trim() !== '' && isWildcardAddress(p))) {
          rewritten.add(hostPath!);
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
      if (config.format !== 'env') {
        for (const hit of wildcardListeners(config.data, listenerTest(ctx.installation.agent))) {
          if (!rewritten.has(hit.path)) remaining.push(hit.path);
        }
      }
    }
    const left = remaining.length > 0
      ? `; still on all interfaces: ${remaining.join(', ')} — rebind ${remaining.length > 1 ? 'them in their' : 'it in its'} own settings`
      : '';
    return done.length > 0
      ? { checkId: 'CFG-001', applied: true, message: done.join('; ') + left }
      : { checkId: 'CFG-001', applied: false, message: `No wildcard gateway listener found to rebind${left}` };
  },
});
