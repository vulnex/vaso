import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

const TLS_LISTENERS = [
  { envKey: 'GATEWAY_TLS_CERT', tomlPath: 'gateway.tls', label: 'Gateway' },
  { envKey: 'HTTP_TLS_CERT', tomlPath: 'http.tls', label: 'HTTP Webhook' },
  { envKey: 'ORCHESTRATOR_TLS_CERT', tomlPath: 'orchestrator.tls', label: 'Orchestrator' },
] as const;

export const ic002 = defineCheck({
  id: 'IC-002',
  name: 'No TLS on Listeners',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check all 3 listeners (gateway, webhook, orchestrator) for TLS configuration',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      for (const listener of TLS_LISTENERS) {
        const envCert = config.data[listener.envKey] as string | undefined;
        const tomlTls = getNestedValue(config.data, listener.tomlPath);
        const tomlCert = getNestedValue(config.data, `${listener.tomlPath}.cert`);

        const hasTls = !!(envCert || tomlTls || tomlCert);

        if (!hasTls) {
          const listenerPrefix = listener.envKey.replace('_TLS_CERT', '');
          const listenerActive = config.raw.includes(listenerPrefix) ||
            getNestedValue(config.data, listener.tomlPath.replace('.tls', ''));

          if (listenerActive) {
            evidence.push({
              file: config.filePath,
              detail: `${listener.label} listener has no TLS certificate configured (${listener.envKey} / ${listener.tomlPath})`,
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All active listeners have TLS configured',
      failed: (n) => `Found ${n} listener(s) without TLS — traffic is unencrypted`,
      fixable: true,
      fixDescription: 'Configure TLS certificates for each active listener (GATEWAY_TLS_CERT, HTTP_TLS_CERT, ORCHESTRATOR_TLS_CERT)',
    });
  },

  async fix() {
    return { checkId: 'IC-002', applied: false, message: 'Manual action required: configure TLS certificates for each listener (GATEWAY_TLS_CERT, HTTP_TLS_CERT, ORCHESTRATOR_TLS_CERT) with valid cert/key file paths' };
  },
});
