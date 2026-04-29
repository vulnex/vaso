import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const opc004 = defineCheck({
  id: 'OPC-004',
  name: 'OpenCode Auto-Share Sessions',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect when OpenCode automatically uploads sessions to the cloud share service',
  supportedAgents: ['opencode'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const share = config.data.share;
      if (typeof share === 'string' && share.toLowerCase() === 'auto') {
        evidence.push({
          file: config.filePath,
          snippet: 'share = "auto"',
          detail: 'Sessions auto-upload to OpenCode cloud — code, prompts, and tool output may leak',
        });
      }
      if (config.data.autoshare === true) {
        evidence.push({
          file: config.filePath,
          snippet: 'autoshare = true',
          detail: 'Deprecated autoshare flag is enabled — sessions auto-upload to cloud',
        });
      }
    }

    const envFlag = ctx.fs.getEnv('OPENCODE_AUTO_SHARE');
    if (envFlag && envFlag !== '0' && envFlag.toLowerCase() !== 'false') {
      evidence.push({
        file: '<env>',
        snippet: `OPENCODE_AUTO_SHARE=${envFlag}`,
        detail: 'Environment forces auto-share regardless of config — sessions upload to cloud',
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'OpenCode session sharing is manual or disabled',
      failed: () => 'OpenCode is configured to auto-share sessions to the cloud',
      fixDescription: 'Set "share": "manual" or "disabled" in opencode.json, and unset OPENCODE_AUTO_SHARE',
    });
  },
});
