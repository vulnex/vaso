import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { gateway, gatewayToml, record, root } from './shared.js';

const LOOPBACK_URL = /^http:\/\/(?:localhost|127(?:\.\d+){3}|\[::1\])(?:[:/]|$)/i;

function plaintext(url: unknown): url is string {
  return typeof url === 'string' && /^http:\/\//i.test(url) && !LOOPBACK_URL.test(url);
}

function entries(v: unknown): Record<string, unknown>[] {
  return Array.isArray(v) ? v.map(record).filter((e): e is Record<string, unknown> => !!e) : [];
}

export const osh006 = defineCheck({
  id: 'OSH-006',
  name: 'OpenShell Extension Services Fail Open or Unencrypted',
  category: 'openshell',
  severity: 'warning',
  description: 'Detect gateway interceptors and supervisor middleware that fail open (`failure_policy = "fail_open"` on a validating binding), let the service choose its own RPC bindings (`binding_policy = "dynamic"`), or talk over plaintext http:// / `allow_insecure_transport` — an outage or a network attacker then bypasses the control they implement',
  supportedAgents: ['openshell'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const file = gatewayToml(ctx)?.filePath ?? '';

    for (const ic of entries(gateway(ctx).interceptors)) {
      const name = String(ic.name ?? '?');
      const bindings = entries(ic.bindings);
      const failOpen = ic.failure_policy === 'fail_open'
        // post_commit bindings must be fail_open and only observe
        && !(bindings.length > 0 && bindings.every(b => Array.isArray(b.phases) && b.phases.every(p => p === 'post_commit')));
      if (failOpen) evidence.push({ file, snippet: `interceptor "${name}": failure_policy = "fail_open"`, detail: 'Requests proceed unchecked whenever the interceptor is down or slow' });
      for (const b of bindings) {
        const phases = Array.isArray(b.phases) ? b.phases : [];
        if (b.failure_policy === 'fail_open' && phases.some(p => p !== 'post_commit')) {
          evidence.push({ file, snippet: `interceptor "${name}" binding ${String(b.rpc ?? b.method ?? '?')}: failure_policy = "fail_open"`, detail: 'This binding is skipped whenever the interceptor fails' });
        }
      }
      if (ic.binding_policy === undefined || ic.binding_policy === 'dynamic') {
        evidence.push({ file, snippet: `interceptor "${name}": binding_policy = "${String(ic.binding_policy ?? 'dynamic')}"`, detail: 'The interceptor decides which RPCs it sees and can modify (gateway logs a startup warning) — pin them with "allowlist" or "exact"' });
      }
      // Interceptors docs: allow_insecure_transport keeps a plaintext endpoint
      // and drops the OpenShell credential — the service cannot tell the
      // gateway from any other client that reaches it
      if (ic.allow_insecure_transport === true) {
        evidence.push({ file, snippet: `interceptor "${name}": ${String(ic.grpc_endpoint ?? '')} (allow_insecure_transport)`, detail: 'Gateway RPCs cross the network unencrypted and the interceptor receives no OpenShell credential' });
      } else if (plaintext(ic.grpc_endpoint)) {
        evidence.push({ file, snippet: `interceptor "${name}": ${ic.grpc_endpoint}`, detail: 'Gateway RPCs and service tokens cross the network unencrypted' });
      }
    }

    for (const mw of entries(record(root(ctx).supervisor)?.middleware)) {
      const name = String(mw.name ?? '?');
      if (mw.allow_insecure_transport === true || plaintext(mw.grpc_endpoint)) {
        evidence.push({ file, snippet: `supervisor middleware "${name}": ${String(mw.grpc_endpoint ?? '')}${mw.allow_insecure_transport === true ? ' (allow_insecure_transport)' : ''}`, detail: 'Sandbox traffic payloads sent to the middleware over plaintext' });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Gateway extension services fail closed over TLS',
      failed: (n) => `Found ${n} weak OpenShell extension service setting(s)`,
      fixDescription: 'Use failure_policy = "fail_closed" and binding_policy = "allowlist" for interceptors, https:// endpoints with tls_ca_cert_path for interceptors and supervisor middleware, and drop allow_insecure_transport',
    });
  },
});
