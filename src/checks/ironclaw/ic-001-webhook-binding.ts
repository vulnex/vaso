import { defineCheck } from '../../core/check-builder.js';
import { updateEnvFile, updateTomlFile } from '../../remediation/config-writer.js';

export const ic001 = defineCheck({
  id: 'IC-001',
  name: 'HTTP Webhook Public Bind',
  category: 'ironclaw',
  severity: 'critical',
  description: 'Check if HTTP webhook listener is bound to 0.0.0.0 (default on port 8080)',
  supportedAgents: ['ironclaw'],

  async run(ctx, h) {
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
    return h.fromEvidence(evidence, {
      passed: 'HTTP webhook is not publicly bound',
      failed: () => 'HTTP webhook is bound to 0.0.0.0 — accessible from all network interfaces',
      fixable: true,
      fixDescription: 'Set HTTP_HOST=127.0.0.1 in .env',
    });
  },

  async fix(ctx) {
    for (const config of ctx.configs) {
      if (config.format === 'env') {
        await updateEnvFile(config.filePath, 'HTTP_HOST', '127.0.0.1');
        return { checkId: 'IC-001', applied: true, message: 'Set HTTP_HOST=127.0.0.1' };
      }
      if (config.format === 'toml') {
        await updateTomlFile(config.filePath, 'http.host', '127.0.0.1');
        return { checkId: 'IC-001', applied: true, message: 'Set HTTP_HOST=127.0.0.1' };
      }
    }
    return { checkId: 'IC-001', applied: false, message: 'No compatible config file found' };
  },
});
