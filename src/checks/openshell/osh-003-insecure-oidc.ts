import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { envTruthy, gateway, gatewayEnv, gatewayToml, record, settingEvidence } from './shared.js';

export const osh003 = defineCheck({
  id: 'OSH-003',
  name: 'OpenShell OIDC Over Plaintext HTTP',
  category: 'openshell',
  severity: 'warning',
  description: 'Detect an OpenShell gateway trusting an OIDC issuer over plaintext HTTP (`dangerously_allow_insecure_http` / OPENSHELL_OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP, or an http:// issuer) — signing keys fetched over HTTP can be swapped, letting forged tokens authenticate as any user or admin',
  supportedAgents: ['openshell'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const oidc = record(gateway(ctx).oidc);
    const toml = gatewayToml(ctx);
    const env = gatewayEnv(ctx);
    const insecure = envTruthy(ctx.configs, 'OPENSHELL_OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP');
    if (insecure === true) {
      evidence.push(settingEvidence(env, 'OPENSHELL_OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP=true', 'Development-only escape hatch enabled in the gateway environment'));
    } else if (insecure === undefined && oidc?.dangerously_allow_insecure_http === true) {
      evidence.push(settingEvidence(toml, 'dangerously_allow_insecure_http = true', 'Development-only escape hatch enabled in [openshell.gateway.oidc]'));
    }
    const envIssuer = env?.data.OPENSHELL_OIDC_ISSUER;
    const issuer = typeof envIssuer === 'string' && envIssuer.trim() ? envIssuer.trim() : oidc?.issuer;
    if (typeof issuer === 'string' && /^http:\/\//i.test(issuer)) {
      evidence.push(settingEvidence(typeof envIssuer === 'string' && envIssuer.trim() ? env : toml, `issuer = ${issuer}`, 'OIDC discovery and JWKS fetched over plaintext HTTP'));
    }
    return h.fromEvidence(evidence, {
      passed: 'OIDC (if configured) uses HTTPS',
      failed: () => 'OpenShell gateway trusts an OIDC issuer over plaintext HTTP',
      fixDescription: 'Use an https:// OIDC issuer and remove dangerously_allow_insecure_http / OPENSHELL_OIDC_DANGEROUSLY_ALLOW_INSECURE_HTTP',
    });
  },
});
