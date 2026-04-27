import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode } from '../../analyzers/ast-analyzer.js';

export const mcp006 = defineCheck({
  id: 'MCP-006',
  name: 'Data Exfiltration Risk',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect sensitive data flowing to network sinks in MCP server source',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
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

    return h.fromEvidence(evidence, {
      passed: 'No data exfiltration patterns found in MCP server source',
      failed: (n) => `Found ${n} data exfiltration risk(s) in MCP server source`,
    });
  },
});
