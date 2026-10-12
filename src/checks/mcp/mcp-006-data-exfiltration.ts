import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode, type DataFlowResult } from '../../analyzers/ast-analyzer.js';

/** Receivers of outbound HTTP calls (`axios.post`, `got.get`, `this.axiosInstance.post`). */
const HTTP_RECEIVER = /^(?:axios\w*|got|ky|http|https|request|superagent|needle|undici|\w*[Aa]xios\w*|\w*[Hh]ttp[Cc]lient)$/;
const OUTBOUND_METHODS = new Set(['fetch', 'request', 'get', 'post', 'put', 'patch']);

/**
 * What counts as exfiltration from an MCP server: file contents, or the whole
 * environment, sent out over HTTP. A single credential from the environment
 * going to an API (`Authorization: Bearer ${API_KEY}`) is how API servers
 * work, and `res.send(data)` / `stream.write(data)` answer the server's own
 * client — neither is reported. (Skill checks keep the broader rule.)
 */
function isExfiltration(r: DataFlowResult): boolean {
  if (r.type !== 'source-to-sink') return false;
  if (r.sourceKind === 'env' && r.source !== 'process.env') return false;
  if (r.sink === 'fetch') return true;
  return OUTBOUND_METHODS.has(r.sink ?? '') && HTTP_RECEIVER.test(r.sinkObject ?? '');
}

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
      // The data-flow analyzer parses JavaScript; Python source has no AST here.
      if (source.language === 'python') continue;

      const results = analyzeCode(source.sourceCode, source.localPath ?? source.serverName);

      const exfilFindings = results.filter(isExfiltration);
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
