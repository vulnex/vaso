import type { CheckModule, ScanContext, CheckResult, FixResult } from '../../core/types.js';
import { updateEnvFile, updateTomlFile } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

export const ic003: CheckModule = {
  id: 'IC-003',
  name: 'Orchestrator Public Bind',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check if gRPC orchestrator is bound to 0.0.0.0 (port 50051)',
  supportedAgents: ['ironclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
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

      // Also flag if no host is set but orchestrator port is configured (defaults to 0.0.0.0 on Linux)
      if (!host && (config.data.ORCHESTRATOR_PORT || getNestedValue(config.data, 'orchestrator.port'))) {
        if (ctx.platform === 'linux') {
          evidence.push({
            file: config.filePath,
            detail: `Orchestrator gRPC on port ${port ?? '50051'} with no explicit host — defaults to 0.0.0.0 on Linux`,
          });
        }
      }
    }

    return {
      id: 'IC-003',
      name: 'Orchestrator Public Bind',
      category: 'ironclaw',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Orchestrator gRPC is not publicly bound'
        : 'Orchestrator gRPC is bound to 0.0.0.0 — accessible from all network interfaces',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set ORCHESTRATOR_HOST=127.0.0.1 in .env or orchestrator.host in config.toml',
    };
  },

  async fix(ctx: ScanContext): Promise<FixResult> {
    for (const config of ctx.configs) {
      if (config.format === 'env') {
        await updateEnvFile(config.filePath, 'ORCHESTRATOR_HOST', '127.0.0.1');
        return { checkId: 'IC-003', applied: true, message: 'Set ORCHESTRATOR_HOST=127.0.0.1' };
      }
      if (config.format === 'toml') {
        await updateTomlFile(config.filePath, 'orchestrator.host', '127.0.0.1');
        return { checkId: 'IC-003', applied: true, message: 'Set ORCHESTRATOR_HOST=127.0.0.1' };
      }
    }
    return { checkId: 'IC-003', applied: false, message: 'No compatible config file found' };
  },
};
