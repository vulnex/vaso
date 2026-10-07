import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { envTruthy, exposed, gateway, gatewayEnv, gatewayToml, settingEvidence } from './shared.js';

export const osh001 = defineCheck({
  id: 'OSH-001',
  name: 'OpenShell Gateway TLS Disabled',
  category: 'openshell',
  severity: 'critical',
  description: 'Detect an OpenShell gateway running without TLS (`disable_tls` / OPENSHELL_DISABLE_TLS). Without TLS the gateway also loses mTLS user authentication — any client that reaches the listener can create sandboxes, read policies and attach providers',
  supportedAgents: ['openshell'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const env = gatewayEnv(ctx);
    if (envTruthy(ctx.configs, 'OPENSHELL_DISABLE_TLS')) {
      evidence.push(settingEvidence(env, 'OPENSHELL_DISABLE_TLS=true', 'TLS disabled by the gateway environment file'));
    } else if (gateway(ctx).disable_tls === true) {
      evidence.push(settingEvidence(gatewayToml(ctx), 'disable_tls = true', 'TLS disabled in [openshell.gateway]'));
    }
    if (evidence.length === 0) return h.passed('Gateway TLS is enabled');
    const where = `${ctx.installation.gateway?.host}:${ctx.installation.gateway?.port}`;
    const remote = exposed(ctx);
    for (const e of evidence) {
      e.detail += remote
        ? ` — listener ${where} is reachable from other hosts in plaintext and without user authentication`
        : ` — listener ${where} is loopback-only, but any local process can drive the gateway without credentials`;
    }
    return h.fromEvidence(evidence, {
      passed: 'Gateway TLS is enabled',
      failed: () => `OpenShell gateway runs without TLS on ${where}`,
      severity: remote ? 'critical' : 'warning',
      fixDescription: 'Remove disable_tls / OPENSHELL_DISABLE_TLS and give the gateway a TLS bundle (openshell-gateway generate-certs), or keep TLS off only behind a trusted TLS-terminating proxy',
    });
  },
});
