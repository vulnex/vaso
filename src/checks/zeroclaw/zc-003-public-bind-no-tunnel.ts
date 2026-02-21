import type { CheckModule, ScanContext, CheckResult, FixResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';
import { updateTomlFile } from '../../remediation/config-writer.js';

export const zc003: CheckModule = {
  id: 'ZC-003',
  name: 'Public Bind Without Tunnel',
  category: 'zeroclaw',
  severity: 'critical',
  description: 'Detect allow_public_bind=true combined with no tunnel provider configured',
  supportedAgents: ['zeroclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const publicBind = getNestedValue(config.data, 'security.allow_public_bind')
        ?? getNestedValue(config.data, 'allow_public_bind');
      const tunnelProvider = getNestedValue(config.data, 'tunnel.provider');

      if (publicBind === true || publicBind === 'true') {
        if (!tunnelProvider || tunnelProvider === 'none') {
          evidence.push({
            file: config.filePath,
            detail: `allow_public_bind=true with tunnel.provider=${tunnelProvider ?? 'not set'} — server is directly exposed to the internet`,
          });
        }
      }
    }

    return {
      id: 'ZC-003',
      name: 'Public Bind Without Tunnel',
      category: 'zeroclaw',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Public bind is disabled or a tunnel provider is configured'
        : 'Server is directly exposed — public bind enabled without tunnel',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true,
      fixDescription: 'Set tunnel.provider to a supported provider (e.g., cloudflare, ngrok) or disable allow_public_bind',
    };
  },

  async fix(ctx: ScanContext): Promise<FixResult> {
    for (const config of ctx.configs) {
      if (config.format === 'toml') {
        await updateTomlFile(config.filePath, 'security.allow_public_bind', false);
        return { checkId: 'ZC-003', applied: true, message: 'Set security.allow_public_bind=false' };
      }
    }
    return { checkId: 'ZC-003', applied: false, message: 'No TOML config file found' };
  },
};
