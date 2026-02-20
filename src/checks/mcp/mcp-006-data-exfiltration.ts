import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';

export const mcp006: CheckModule = {
  id: 'MCP-006',
  name: 'Data Exfiltration Risk',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect sensitive data flowing to network sinks in MCP server source',
  supportedAgents: ['mcp'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const sources = ctx.mcpServerSources ?? [];

    for (const source of sources) {
      if (!source.sourceCode) continue;

      const results = analyzeCode(source.sourceCode, source.localPath ?? source.serverName);

      const exfilFindings = results.filter(r => r.type === 'source-to-sink');
      const suspiciousNet = results.filter(r => r.type === 'suspicious-network');

      for (const finding of exfilFindings) {
        evidence.push({
          file: source.localPath ?? source.serverName,
          line: finding.line,
          snippet: finding.snippet,
          detail: finding.description,
        });
      }

      for (const finding of suspiciousNet) {
        evidence.push({
          file: source.localPath ?? source.serverName,
          line: finding.line,
          snippet: finding.snippet,
          detail: finding.description,
        });
      }
    }

    return {
      id: 'MCP-006',
      name: 'Data Exfiltration Risk',
      category: 'mcp',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No data exfiltration patterns found in MCP server source'
        : `Found ${evidence.length} data exfiltration risk(s) in MCP server source`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
