import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

function specToString(spec: unknown): string | undefined {
  if (typeof spec === 'string') return spec;
  if (Array.isArray(spec) && typeof spec[0] === 'string') return spec[0];
  return undefined;
}

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
      const plugins = config.data.plugin;
      if (!Array.isArray(plugins)) continue;

      for (const entry of plugins) {
        const spec = specToString(entry);
        if (!spec) continue;
        if (spec.startsWith('http://')) {
          evidence.push({
            file: config.filePath,
            snippet: `plugin entry: ${spec}`,
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
