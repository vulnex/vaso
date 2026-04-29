import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

function specToString(spec: unknown): string | undefined {
  if (typeof spec === 'string') return spec;
  if (Array.isArray(spec) && typeof spec[0] === 'string') return spec[0];
  return undefined;
}

// Relative file specs (./, ../, plain `file.ts`, plain `name`) load whichever
// plugin happens to exist in the active project — the same risk pattern as
// CC-006 (project-MCP auto-trust): code is executed in-process based on the
// CWD, not on a centrally-controlled trust list.
export const opc010 = defineCheck({
  id: 'OPC-010',
  name: 'OpenCode Project-Relative Plugin Path',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect plugin entries that resolve relative to the active project — any project can ship matching code',
  supportedAgents: ['opencode'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const plugins = config.data.plugin;
      if (!Array.isArray(plugins)) continue;

      for (const entry of plugins) {
        const spec = specToString(entry);
        if (!spec) continue;

        if (spec.startsWith('./') || spec.startsWith('../')) {
          evidence.push({
            file: config.filePath,
            snippet: `plugin entry: ${spec}`,
            detail: 'Plugin path is relative — resolves under whichever project OpenCode is run from',
          });
          continue;
        }

        // file:// URLs are explicit and pin the path; URLs with absolute paths
        // (file:///abs/path) are fine. file:./relative is NOT.
        if (/^file:(?!\/\/)/.test(spec) || /^file:\/\/(?!\/)/.test(spec)) {
          evidence.push({
            file: config.filePath,
            snippet: `plugin entry: ${spec}`,
            detail: 'Plugin file: URL is not absolute — resolution depends on the active project',
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'OpenCode plugin entries use absolute paths or stable identifiers',
      failed: (n) => `Found ${n} project-relative OpenCode plugin entr${n === 1 ? 'y' : 'ies'}`,
      fixDescription: 'Use absolute file paths (file:///abs/path/plugin.ts) or npm package names for plugins',
    });
  },
});
