import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { updateEnvFile } from '../../remediation/config-writer.js';

const PUBLIC_HOSTS = new Set(['0.0.0.0', '::', '*']);

export const nc004 = defineCheck({
  id: 'NC-004',
  name: 'NANOCLAW_PORT Bound Publicly',
  category: 'nanoclaw',
  severity: 'warning',
  description: 'Detect when NANOCLAW_HOST in `.nanoclaw.env` is set to 0.0.0.0 (or absent while NANOCLAW_PORT is set), exposing the agent listener on all network interfaces.',
  supportedAgents: ['nanoclaw'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('.nanoclaw.env')) continue;

      const port = config.data.NANOCLAW_PORT;
      const host = config.data.NANOCLAW_HOST;
      if (!port) continue;

      if (typeof host === 'string' && PUBLIC_HOSTS.has(host)) {
        evidence.push({
          file: config.filePath,
          detail: `NANOCLAW_HOST=${host} with NANOCLAW_PORT=${port} — listener exposed on all interfaces`,
        });
      } else if (host === undefined || (typeof host === 'string' && host === '')) {
        evidence.push({
          file: config.filePath,
          detail: `NANOCLAW_PORT=${port} set without NANOCLAW_HOST — defaults are framework-dependent; pin NANOCLAW_HOST=127.0.0.1 explicitly`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'NANOCLAW listener is loopback-bound or not configured',
      failed: () => 'NANOCLAW listener is publicly bound or unspecified',
      fixable: true,
      fixDescription: 'Set NANOCLAW_HOST=127.0.0.1 in .nanoclaw.env',
    });
  },

  async fix(ctx) {
    let fixed = 0;
    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('.nanoclaw.env')) continue;
      try {
        await updateEnvFile(config.filePath, 'NANOCLAW_HOST', '127.0.0.1');
        fixed++;
      } catch {
        // skip
      }
    }
    return {
      checkId: 'NC-004',
      applied: fixed > 0,
      message: fixed > 0 ? 'Set NANOCLAW_HOST=127.0.0.1' : 'No .nanoclaw.env to update',
    };
  },
});
