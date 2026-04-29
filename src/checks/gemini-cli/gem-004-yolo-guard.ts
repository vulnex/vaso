import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const gem004 = defineCheck({
  id: 'GEM-004',
  name: 'Gemini YOLO Mode Guard Removed',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when security.disableYoloMode is explicitly set to false — `--yolo` CLI flag remains usable',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const security = config.data.security as Record<string, unknown> | undefined;
      if (!security || typeof security !== 'object') continue;
      if (security.disableYoloMode === false) {
        evidence.push({
          file: config.filePath,
          snippet: 'security.disableYoloMode = false',
          detail: 'YOLO guard explicitly off — `gemini --yolo` will auto-approve every tool call this session',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Gemini YOLO mode guard is not explicitly disabled',
      failed: () => 'Gemini security.disableYoloMode is explicitly off — anyone can launch yolo sessions',
      fixDescription: 'Set security.disableYoloMode: true in ~/.gemini/settings.json to block --yolo at the CLI layer',
    });
  },
});
