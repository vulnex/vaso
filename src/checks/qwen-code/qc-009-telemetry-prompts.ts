import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const qc009 = defineCheck({
  id: 'QC-009',
  name: 'Qwen Telemetry Logs Prompts',
  category: 'coding-agent',
  severity: 'info',
  description: 'Detect telemetry.logPrompts set to true — user prompts are sent to telemetry',
  supportedAgents: ['qwen-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const telemetry = config.data.telemetry as Record<string, unknown> | undefined;
      if (!telemetry || typeof telemetry !== 'object') continue;
      if (telemetry.logPrompts === true) {
        evidence.push({
          file: config.filePath,
          snippet: 'telemetry.logPrompts = true',
          detail: 'Prompts (which may contain code, secrets, or PII) are sent to the telemetry endpoint',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Qwen telemetry does not log prompt content',
      failed: () => 'Qwen telemetry.logPrompts is enabled — prompt content is uploaded',
      fixDescription: 'Set telemetry.logPrompts: false in ~/.qwen/settings.json (or omit telemetry entirely)',
    });
  },
});
