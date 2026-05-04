import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

const TRUTHY = /^(?:1|true|yes|on)$/i;

export const hm008 = defineCheck({
  id: 'HM-008',
  name: 'Hermes Tool-Call Approvals Disabled',
  category: 'hermes',
  severity: 'critical',
  description: 'approvals.mode set to "off" in cli-config.yaml or HERMES_YOLO_MODE truthy in .env — tool calls (including terminal commands) execute without operator confirmation.',
  supportedAgents: ['hermes'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of ctx.configs) {
      if (config.filePath.endsWith('cli-config.yaml') || config.filePath.endsWith('config.yaml')) {
        const mode = getNestedValue(config.data, 'approvals.mode');
        if (typeof mode === 'string' && mode.toLowerCase() === 'off') {
          evidence.push({
            file: config.filePath,
            snippet: `approvals.mode: ${mode}`,
            detail: 'Tool-call approval prompts disabled — every action runs without confirmation',
          });
        }
      }
      if (config.format === 'env') {
        const yolo = config.data.HERMES_YOLO_MODE;
        if (typeof yolo === 'string' && TRUTHY.test(yolo.trim())) {
          evidence.push({
            file: config.filePath,
            snippet: `HERMES_YOLO_MODE=${yolo}`,
            detail: 'Persistent YOLO mode bypasses dangerous-command prompts for every Hermes session',
          });
        }
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Hermes tool-call approvals are enabled',
      failed: (n) => `Found ${n} approval-bypass setting(s) — every tool call runs without confirmation`,
      fixDescription: 'Set approvals.mode: manual (or smart) in cli-config.yaml; remove HERMES_YOLO_MODE from .env',
    });
  },
});
