import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { describeEndpoint, endpoints, record, sandboxPolicies } from './shared.js';

const INSPECTED = new Set(['rest', 'websocket', 'graphql', 'mcp', 'json-rpc']);

export const osh012 = defineCheck({
  id: 'OSH-012',
  name: 'OpenShell Sandbox Egress Not Inspected or Enforced',
  category: 'openshell',
  severity: 'warning',
  description: 'Detect sandbox endpoints the proxy cannot police: `tls: skip` (no inspection, no credential rewriting), `allow_uninspected_credentials`, an MCP endpoint allowing every method, HTTP endpoints without an inspected `protocol` (any method/path), raw `protocol: tcp` passthrough, `access: full`, and rules left in `enforcement: audit` (violations logged but forwarded)',
  supportedAgents: ['openshell'],

  async run(ctx, h) {
    const warning: Evidence[] = [];
    const info: Evidence[] = [];
    for (const { ref, rule, endpoint: e } of endpoints(await sandboxPolicies(ctx))) {
      const where = `network_policies.${rule} → ${describeEndpoint(e)}`;
      const add = (list: Evidence[], snippet: string, detail: string) =>
        list.push({ file: ref.file, snippet: `${where}: ${snippet}`, detail: `${ref.source}: ${detail}` });
      const protocol = typeof e.protocol === 'string' ? e.protocol : undefined;

      if (e.tls === 'skip') add(warning, 'tls: skip', 'Traffic is relayed encrypted — no request inspection or credential rewriting');
      if (e.allow_uninspected_credentials === true) add(warning, 'allow_uninspected_credentials: true', 'Provider credentials flow to this endpoint without request inspection');
      if (protocol === 'mcp' && record(e.mcp)?.allow_all_known_mcp_methods === true) add(warning, 'mcp.allow_all_known_mcp_methods: true', 'Every MCP method (all tools) is allowed unless a deny rule matches');
      if (!protocol && e.tls !== 'skip') add(info, 'no protocol', 'Host, port and program are checked, but any HTTP method and path is allowed');
      // Network rules docs: tcp opens a plain connection and checks no request rules
      if (protocol === 'tcp') add(info, 'protocol: tcp', 'Raw TCP passthrough — host, port and program are checked, the traffic itself is not');
      if (protocol && INSPECTED.has(protocol)) {
        if (e.access === 'full') add(info, 'access: full', 'Inspection is on but every method and path is allowed');
        if ((e.enforcement ?? 'audit') === 'audit' && (e.rules !== undefined || e.access !== undefined)) {
          add(info, `enforcement: ${String(e.enforcement ?? 'audit (default)')}`, 'Rule violations are logged and forwarded, not blocked');
        }
      }
    }
    return h.fromEvidence([...warning, ...info], {
      passed: 'Sandbox egress is inspected and enforced',
      failed: (n) => `Found ${n} OpenShell endpoint setting(s) that weaken egress inspection`,
      severity: warning.length > 0 ? undefined : 'info',
      fixDescription: 'Use protocol: rest/websocket/graphql/mcp with explicit rules or access: read-only, switch to enforcement: enforce once audited, keep TLS termination on (drop tls: skip) and avoid allow_uninspected_credentials',
    });
  },
});
