import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

import { opencodePluginSpecs } from './schema.js';

export const opc005 = defineCheck({
  id: 'OPC-005',
  name: 'OpenCode Plugin Loaded from Unsafe Source',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect OpenCode plugins loaded from plaintext HTTP URLs (insecure remote code execution)',
  supportedAgents: ['opencode'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      for (const { spec, key } of opencodePluginSpecs(config.data)) {
        if (spec.startsWith('http://')) {
          evidence.push({
            file: config.filePath,
            snippet: `${key} entry: ${spec}`,
            detail: 'Plugin source is plaintext HTTP — code can be tampered in transit and runs in-process',
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'OpenCode plugins are loaded from safe sources',
      failed: (n) => `Found ${n} OpenCode plugin(s) loaded over plaintext HTTP`,
      fixDescription: 'Use https:// URLs, npm package names, or local file paths for plugin sources',
    });
  },
});
