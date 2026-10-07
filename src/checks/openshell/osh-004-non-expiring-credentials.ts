import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { updateConfigValue } from '../../remediation/config-writer.js';
import { exposed, gateway, gatewayToml, record, settingEvidence } from './shared.js';

const DEFAULT_SSH_TTL = 86400;

export const osh004 = defineCheck({
  id: 'OSH-004',
  name: 'OpenShell Non-Expiring Session Credentials',
  category: 'openshell',
  severity: 'warning',
  description: 'Detect OpenShell sessions that never expire: `ssh_session_ttl_secs = 0` (sandbox SSH tokens valid forever), and sandbox gateway JWTs without a TTL (`gateway_jwt.ttl_secs` unset or 0) on a gateway reachable from other hosts or shared through OIDC — a stolen token stays usable for the life of the sandbox',
  supportedAgents: ['openshell'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const gw = gateway(ctx);
    const toml = gatewayToml(ctx);
    if (gw.ssh_session_ttl_secs === 0) {
      evidence.push(settingEvidence(toml, 'ssh_session_ttl_secs = 0', 'Sandbox SSH session tokens never expire (default 24 h)'));
    }
    const shared = exposed(ctx) || ctx.installation.gateway?.authMode === 'oidc';
    const jwt = record(gw.gateway_jwt);
    const ttl = jwt?.ttl_secs;
    if (shared && toml && (ttl === undefined || ttl === 0)) {
      evidence.push(settingEvidence(toml, ttl === 0 ? 'gateway_jwt.ttl_secs = 0' : 'gateway_jwt.ttl_secs unset',
        'Shared gateway issues sandbox credentials that never expire — the docs require a TTL for shared deployments'));
    }
    return h.fromEvidence(evidence, {
      passed: 'Gateway session credentials expire',
      failed: (n) => `Found ${n} non-expiring OpenShell session credential setting(s)`,
      fixable: gw.ssh_session_ttl_secs === 0,
      fixDescription: 'Remove ssh_session_ttl_secs = 0 (or set it to 86400) and, on shared gateways, set [openshell.gateway.gateway_jwt] ttl_secs (e.g. 3600); restart the gateway',
    });
  },

  async fix(ctx) {
    const toml = gatewayToml(ctx);
    if (!toml || gateway(ctx).ssh_session_ttl_secs !== 0) {
      return { checkId: 'OSH-004', applied: false, message: 'No ssh_session_ttl_secs = 0 to fix — set gateway_jwt.ttl_secs manually' };
    }
    await updateConfigValue(toml, 'openshell.gateway.ssh_session_ttl_secs', DEFAULT_SSH_TTL);
    return { checkId: 'OSH-004', applied: true, message: `Set ssh_session_ttl_secs = ${DEFAULT_SSH_TTL} (24 h) — restart the gateway to apply` };
  },
});
