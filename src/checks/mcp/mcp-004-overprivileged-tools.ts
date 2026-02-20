import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';

export const mcp004: CheckModule = {
  id: 'MCP-004',
  name: 'Overprivileged Tools',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect MCP servers with exec/shell/write capabilities in source code',
  supportedAgents: ['mcp'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const sources = ctx.mcpServerSources ?? [];

    for (const source of sources) {
      if (!source.sourceCode) continue;

      const results = analyzeCode(source.sourceCode, source.localPath ?? source.serverName);

      const execFindings = results.filter(r => r.type === 'eval-exec');
      const fsFindings = results.filter(r => r.type === 'fs-access');

      for (const finding of execFindings) {
        evidence.push({
          file: source.localPath ?? source.serverName,
          line: finding.line,
          snippet: finding.snippet,
          detail: `Command execution: ${finding.description}`,
        });
      }

      for (const finding of fsFindings) {
        evidence.push({
          file: source.localPath ?? source.serverName,
          line: finding.line,
          snippet: finding.snippet,
          detail: `Sensitive file access: ${finding.description}`,
        });
      }
    }

    return {
      id: 'MCP-004',
      name: 'Overprivileged Tools',
      category: 'mcp',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No overprivileged operations found in MCP server source'
        : `Found ${evidence.length} overprivileged operation(s) in MCP server source`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
