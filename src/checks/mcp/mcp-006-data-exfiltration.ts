import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode, type DataFlowResult } from '../../analyzers/ast-analyzer.js';

/** Receivers of outbound HTTP calls (`axios.post`, `got.get`, `this.axiosInstance.post`). */
const HTTP_RECEIVER = /^(?:axios\w*|got|ky|http|https|request|superagent|needle|undici|\w*[Aa]xios\w*|\w*[Hh]ttp[Cc]lient)$/;
const OUTBOUND_METHODS = new Set(['fetch', 'request', 'get', 'post', 'put', 'patch']);

/**
 * What counts as exfiltration from an MCP server: file contents, or the whole
 * environment, sent out over HTTP or a client WebSocket the server opened. A single credential from the environment
 * going to an API (`Authorization: Bearer ${API_KEY}`) is how API servers
 * work, and `res.send(data)` / `stream.write(data)` answer the server's own
 * client — neither is reported. (Skill checks keep the broader rule.)
 */
function isExfiltration(r: DataFlowResult): boolean {
  if (r.type !== 'source-to-sink') return false;
  if (r.sourceKind === 'env' && !r.wholeEnv) return false;
  // Flows found by following the value (callbacks, transforms, helpers) count
  // only for a credential store or the whole environment: a tool handler
  // reading the file it was asked for and uploading it is the tool's job
  if (r.derived && r.sourcePath !== 'credential' && !r.wholeEnv) return false;
  if (r.sink === 'fetch') return true;
  // Sent on a socket the server opened to a remote endpoint (`new WebSocket(url)`)
  if (r.sink === 'send' && r.socketClient) return true;
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
      // Opening a WebSocket sends nothing by itself — a CDP/debugger or
      // realtime client (@metamask/device-mcp) is not exfiltration
      const suspiciousNet = results.filter(r => r.type === 'suspicious-network' && r.sink !== 'WebSocket');

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
