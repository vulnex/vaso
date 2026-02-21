import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';

export const ic001: CheckModule = {
  id: 'IC-001',
  name: 'HTTP Webhook Public Bind',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check if HTTP webhook listener is bound to 0.0.0.0 (default on port 8080)',
  supportedAgents: ['ironclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];
    for (const config of ctx.configs) {
      const host = config.data.HTTP_HOST as string | undefined;
      const port = config.data.HTTP_PORT as string | undefined;
      if (host === '0.0.0.0' || (!host && config.raw.includes('HTTP_PORT'))) {
        evidence.push({
          file: config.filePath,
          detail: `HTTP webhook bound to ${host ?? '0.0.0.0 (default)'}:${port ?? '8080'} — publicly accessible`,
        });
      }
    }
    return {
      id: 'IC-001', name: 'HTTP Webhook Public Bind', category: 'ironclaw',
      severity: 'critical', passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'HTTP webhook is not publicly bound'
        : 'HTTP webhook is bound to 0.0.0.0 — accessible from all network interfaces',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true, fixDescription: 'Set HTTP_HOST=127.0.0.1 in .env',
    };
  },
};
