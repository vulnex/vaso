import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

export const ic003 = defineCheck({
  id: 'IC-003',
  name: 'Orchestrator Public Bind',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check if gRPC orchestrator is bound to 0.0.0.0 (port 50051)',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
    const evidence = [];

    for (const config of ctx.configs) {
      const host =
        (config.data.ORCHESTRATOR_HOST as string | undefined) ??
        (getNestedValue(config.data, 'orchestrator.host') as string | undefined);

      const port =
        (config.data.ORCHESTRATOR_PORT as string | undefined) ??
        (getNestedValue(config.data, 'orchestrator.port') as string | undefined);

      const WILDCARD_BINDS = ['0.0.0.0', '[::]', '::'];

      if (typeof host === 'string' && WILDCARD_BINDS.includes(host)) {
        evidence.push({
          file: config.filePath,
          detail: `Orchestrator gRPC bound to ${host}:${port ?? '50051'} — publicly accessible`,
        });
      }

      if (!host && (config.data.ORCHESTRATOR_PORT || getNestedValue(config.data, 'orchestrator.port'))) {
        if (ctx.platform === 'linux') {
          evidence.push({
            file: config.filePath,
            detail: `Orchestrator gRPC on port ${port ?? '50051'} with no explicit host — defaults to 0.0.0.0 on Linux`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Orchestrator gRPC is not publicly bound',
      failed: () => 'Orchestrator gRPC is bound to 0.0.0.0 — accessible from all network interfaces',
      fixable: true,
      fixDescription: 'Set ORCHESTRATOR_HOST=127.0.0.1 in .env or orchestrator.host in config.toml',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(ctx.configs, {
      checkId: 'IC-003',
      env: 'ORCHESTRATOR_HOST',
      path: 'orchestrator.host',
      value: '127.0.0.1',
      message: 'Set ORCHESTRATOR_HOST=127.0.0.1',
    });
  },
});
