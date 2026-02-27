import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { extractToolDefinitions, diffToolBaseline } from '../../mcp/tool-baseline.js';

export const mcp020: CheckModule = {
  id: 'MCP-020',
  name: 'Tool Definition Rug Pull',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect silent changes to MCP tool definitions between scans',
  supportedAgents: ['mcp'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const sources = ctx.mcpServerSources ?? [];
    let anyFirstScan = false;
    let totalChanges = 0;

    for (const source of sources) {
      if (!source.sourceCode) continue;

      const tools = extractToolDefinitions(source.sourceCode);
      if (tools.length === 0) continue;

      const { diff, isFirstScan } = await diffToolBaseline(source.serverName, tools);

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
      return {
        id: 'MCP-020',
        name: 'Tool Definition Rug Pull',
        category: 'mcp',
        severity: 'info',
        passed: true,
        message: 'MCP tool definition baseline established — changes will be detected on subsequent scans',
      };
    }

    return {
      id: 'MCP-020',
      name: 'Tool Definition Rug Pull',
      category: 'mcp',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'MCP tool definitions unchanged since last scan'
        : `Found ${totalChanges} tool definition change(s) across MCP servers — possible rug pull`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
