import type { CheckModule, ScanContext, CheckResult, FixResult } from '../../core/types.js';
import { updateEnvFile, updateTomlFile } from '../../remediation/config-writer.js';
import { randomBytes } from 'node:crypto';
import { getNestedValue } from '../../core/utils.js';

export const ic004: CheckModule = {
  id: 'IC-004',
  name: 'Gateway Auth Token Missing',
  category: 'ironclaw',
  severity: 'warning',
  description: 'Check if GATEWAY_AUTH_TOKEN is set — ephemeral random tokens are not persistent across restarts',
  supportedAgents: ['ironclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const token =
        (config.data.GATEWAY_AUTH_TOKEN as string | undefined) ??
        (getNestedValue(config.data, 'gateway.auth_token') as string | undefined) ??
        (getNestedValue(config.data, 'gateway.authToken') as string | undefined);

      if (!token || token.trim() === '') {
        evidence.push({
          file: config.filePath,
          detail: 'GATEWAY_AUTH_TOKEN is not set or empty — gateway uses ephemeral random tokens that are not persistent',
        });
      }
    }

    return {
      id: 'IC-004',
      name: 'Gateway Auth Token Missing',
      category: 'ironclaw',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Gateway auth token is explicitly configured'
        : 'Gateway auth token is not set — ephemeral tokens reset on restart',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set a persistent GATEWAY_AUTH_TOKEN in .env or gateway.auth_token in config.toml',
    };
  },

  async fix(ctx: ScanContext): Promise<FixResult> {
    const token = randomBytes(32).toString('hex');
    for (const config of ctx.configs) {
      if (config.format === 'env') {
        await updateEnvFile(config.filePath, 'GATEWAY_AUTH_TOKEN', token);
        return { checkId: 'IC-004', applied: true, message: 'Generated and set persistent GATEWAY_AUTH_TOKEN' };
      }
      if (config.format === 'toml') {
        await updateTomlFile(config.filePath, 'gateway.auth_token', token);
        return { checkId: 'IC-004', applied: true, message: 'Generated and set persistent GATEWAY_AUTH_TOKEN' };
      }
    }
    return { checkId: 'IC-004', applied: false, message: 'No compatible config file found' };
  },
};
