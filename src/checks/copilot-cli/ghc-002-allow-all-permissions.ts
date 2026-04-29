import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const ghc002 = defineCheck({
  id: 'GHC-002',
  name: 'Copilot CLI Allow-All Permissions',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect allowAllPermissions:true in settings.json — every tool call auto-approves',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('settings.json')) continue;
      if (config.data.allowAllPermissions === true) {
        evidence.push({
          file: config.filePath,
          snippet: 'allowAllPermissions = true',
          detail: 'Every tool call (including shell commands) auto-approves without prompting',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Copilot CLI requires per-tool approval',
      failed: () => 'Copilot CLI allowAllPermissions is enabled — every tool auto-approves',
      fixDescription: 'Set allowAllPermissions: false (or remove it) in ~/.copilot/settings.json',
    });
  },
});
