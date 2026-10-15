import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { describeEndpoint, endpoints, sandboxPolicies } from './shared.js';

function prefixLength(cidr: string): number | undefined {
  const m = /^\s*([0-9a-f.:]+)(?:\/(\d{1,3}))?\s*$/i.exec(cidr);
  if (!m) return undefined;
  const v6 = m[1].includes(':');
  return m[2] !== undefined ? Number(m[2]) : v6 ? 128 : 32;
}

export const osh013 = defineCheck({
  id: 'OSH-013',
  name: 'OpenShell Sandbox Reaches Broad Network Ranges',
  category: 'openshell',
  severity: 'warning',
  description: 'Detect sandbox endpoints opened to wide address ranges (`allowed_ips` of /8 or wider, including 0.0.0.0/0 — accepted by the 0.1.2 gateway) or to services on the gateway host itself (`host.openshell.internal`) — they defeat the private-address SSRF guard and expose internal networks to the agent',
  supportedAgents: ['openshell'],

  async run(ctx, h) {
    const critical: Evidence[] = [];
    const warning: Evidence[] = [];
    for (const { ref, rule, endpoint: e } of endpoints(await sandboxPolicies(ctx))) {
      const where = `network_policies.${rule} → ${describeEndpoint(e)}`;
      // With a host, allowed_ips only constrain what that name may resolve to
      // ("host + allowed_ips — domain must resolve to an IP in the allowlist",
      // OpenShell generate-sandbox-policy skill, Private IP Destinations); a
      // range opens to any name only on a hostless endpoint
      const named = typeof e.host === 'string' && e.host.trim() !== '' && e.host.trim() !== '*';
      for (const cidr of !named && Array.isArray(e.allowed_ips) ? e.allowed_ips : []) {
        if (typeof cidr !== 'string') continue;
        const len = prefixLength(cidr);
        const v6 = cidr.includes(':');
        if (len === undefined || len > (v6 ? 32 : 8)) continue;
        (len === 0 ? critical : warning).push({
          file: ref.file,
          snippet: `${where}: allowed_ips ${cidr}`,
          detail: `${ref.source}: ${len === 0 ? 'every address, private ranges included' : `a /${len} range`} is reachable from the sandbox`,
        });
      }
      if (typeof e.host === 'string' && e.host.toLowerCase() === 'host.openshell.internal') {
        warning.push({ file: ref.file, snippet: where, detail: `${ref.source}: the sandbox can reach services on the gateway host` });
      }
    }
    return h.fromEvidence([...critical, ...warning], {
      passed: 'Sandbox endpoints target specific hosts',
      failed: (n) => `Found ${n} OpenShell endpoint(s) opened to broad network ranges`,
      severity: critical.length > 0 ? 'critical' : undefined,
      fixDescription: 'Declare exact hostnames, or scope allowed_ips to the single hosts needed (e.g. 10.0.5.20/32); avoid host.openshell.internal unless the service on the gateway host is meant for the agent',
    });
  },
});
