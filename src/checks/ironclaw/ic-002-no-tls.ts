import type { CheckModule, ScanContext, CheckResult, FixResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

const TLS_LISTENERS = [
  { envKey: 'GATEWAY_TLS_CERT', tomlPath: 'gateway.tls', label: 'Gateway' },
  { envKey: 'HTTP_TLS_CERT', tomlPath: 'http.tls', label: 'HTTP Webhook' },
  { envKey: 'ORCHESTRATOR_TLS_CERT', tomlPath: 'orchestrator.tls', label: 'Orchestrator' },
] as const;

export const ic002: CheckModule = {
  id: 'IC-002',
  name: 'No TLS on Listeners',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check all 3 listeners (gateway, webhook, orchestrator) for TLS configuration',
  supportedAgents: ['ironclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      for (const listener of TLS_LISTENERS) {
        const envCert = config.data[listener.envKey] as string | undefined;
        const tomlTls = getNestedValue(config.data, listener.tomlPath);
        const tomlCert = getNestedValue(config.data, `${listener.tomlPath}.cert`);

        const hasTls = !!(envCert || tomlTls || tomlCert);

        if (!hasTls) {
          // Only flag if the listener appears to be configured at all
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

    return {
      id: 'IC-002',
      name: 'No TLS on Listeners',
      category: 'ironclaw',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'All active listeners have TLS configured'
        : `Found ${evidence.length} listener(s) without TLS — traffic is unencrypted`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Configure TLS certificates for each active listener (GATEWAY_TLS_CERT, HTTP_TLS_CERT, ORCHESTRATOR_TLS_CERT)',
    };
  },

  async fix(_ctx: ScanContext): Promise<FixResult> {
    return { checkId: 'IC-002', applied: false, message: 'Manual action required: configure TLS certificates for each listener (GATEWAY_TLS_CERT, HTTP_TLS_CERT, ORCHESTRATOR_TLS_CERT) with valid cert/key file paths' };
  },
};
