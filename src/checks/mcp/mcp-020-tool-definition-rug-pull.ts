import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import {
  extractToolDefinitions,
  diffToolBaseline,
  defaultBaselineStore,
} from '../../mcp/tool-baseline.js';

export const mcp020 = defineCheck({
  id: 'MCP-020',
  name: 'Tool Definition Rug Pull',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect silent changes to MCP tool definitions between scans',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const sources = ctx.mcpServerSources ?? [];
    const store = ctx.mcpToolBaselineStore ?? defaultBaselineStore();
    const hostname = ctx.fs.hostname();
    let anyFirstScan = false;
    let totalChanges = 0;

    for (const source of sources) {
      if (!source.sourceCode) continue;

      const tools = extractToolDefinitions(source.sourceCode);
      if (tools.length === 0) continue;

      const { diff, isFirstScan } = await diffToolBaseline(store, source, tools, hostname);

      if (isFirstScan) {
        anyFirstScan = true;
        continue;
      }

      for (const changed of diff.changed) {
        totalChanges++;
        evidence.push({
          file: source.localPath ?? source.serverName,
          detail: `Tool "${changed.name}" definition changed in server "${source.serverName}" (hash ${changed.oldHash.slice(0, 8)}→${changed.newHash.slice(0, 8)})`,
        });
      }

      for (const added of diff.added) {
        totalChanges++;
        evidence.push({
          file: source.localPath ?? source.serverName,
          detail: `New tool "${added}" appeared in server "${source.serverName}" since last scan`,
        });
      }

      for (const removed of diff.removed) {
        totalChanges++;
        evidence.push({
          file: source.localPath ?? source.serverName,
          detail: `Tool "${removed}" was removed from server "${source.serverName}" since last scan`,
        });
      }
    }

    if (anyFirstScan && evidence.length === 0) {
      return h.result({
        passed: true,
        message: 'MCP tool definition baseline established — changes will be detected on subsequent scans',
        severity: 'info',
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'MCP tool definitions unchanged since last scan',
      failed: () => `Found ${totalChanges} tool definition change(s) across MCP servers — possible rug pull`,
    });
  },
});
