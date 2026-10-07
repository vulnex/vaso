import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { exposed, gatewayToml, record, gateway, settingEvidence } from './shared.js';

export const osh002 = defineCheck({
  id: 'OSH-002',
  name: 'OpenShell Gateway Accepts Unauthenticated Users',
  category: 'openshell',
  severity: 'critical',
  description: 'Detect `[openshell.gateway.auth] allow_unauthenticated_users = true` — the gateway accepts CLI/API calls without OIDC or mTLS credentials, so anyone who reaches it manages every sandbox, policy and provider',
  supportedAgents: ['openshell'],

  async run(ctx, h) {
    if (record(gateway(ctx).auth)?.allow_unauthenticated_users !== true) {
      return h.passed('Gateway requires authenticated users');
    }
    const remote = exposed(ctx);
    return h.fromEvidence([settingEvidence(gatewayToml(ctx), 'allow_unauthenticated_users = true',
      remote
        ? `Gateway listens on ${ctx.installation.gateway?.host} — any host that reaches it is treated as a gateway user`
        : 'Any local process can manage sandboxes, policies and providers (documented as a local-development / trusted-proxy escape hatch)')], {
      passed: 'Gateway requires authenticated users',
      failed: () => 'OpenShell gateway accepts unauthenticated users',
      severity: remote ? 'critical' : 'warning',
      fixable: true,
      fixDescription: 'Set [openshell.gateway.auth] allow_unauthenticated_users = false and restart the gateway; use mTLS (local) or OIDC (shared gateways)',
    });
  },

  async fix(ctx) {
    const toml = gatewayToml(ctx);
    return fixFirstConfig(toml ? [toml] : [], {
      checkId: 'OSH-002',
      path: 'openshell.gateway.auth.allow_unauthenticated_users',
      value: false,
      message: 'Set allow_unauthenticated_users = false — restart the gateway to apply',
      noConfigMessage: 'No OpenShell gateway TOML found',
    });
  },
});
