import type { Evidence, Severity } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { findExternalContentFlows, type ExternalContentFlow } from '../../analyzers/tool-result-flow.js';

/**
 * MCP-007 — external content returned as a tool result. Fetched pages and
 * read files go to the model verbatim; if someone else writes that content,
 * they can plant instructions in it (indirect prompt injection). Traced from
 * the HTTP call or file read to the `{ type: 'text', text }` block (JS), or
 * from the HTTP call in a tool function (Python) — see tool-result-flow.
 *
 * Warning when anyone can write the content: a URL the caller chooses, or a
 * host where anyone can publish. A fixed API, or a file the server reads, is
 * reported at info — a reminder that the content is passed through unfiltered.
 */

function describe(flow: ExternalContentFlow): { detail: string; severity: Severity } {
  if (flow.via === 'file') {
    return { severity: 'info', detail: `File content (${flow.source}) is returned to the model as a tool result unfiltered — instructions planted in the file reach the model` };
  }
  if (flow.callerChosenUrl) {
    return { severity: 'warning', detail: `Fetches a URL the caller chooses (${flow.source}) and returns the response to the model unfiltered — any page, including one an attacker wrote, can inject instructions` };
  }
  if (flow.openContentHost) {
    return { severity: 'warning', detail: `Returns content from ${flow.host}, where anyone can publish, to the model unfiltered (${flow.source}) — planted text reaches the model as tool output` };
  }
  return { severity: 'info', detail: `Returns an HTTP response${flow.host ? ` from ${flow.host}` : ''} (${flow.source}) to the model unfiltered — whoever controls that service controls the text the model reads` };
}

export const mcp007 = defineCheck({
  id: 'MCP-007',
  name: 'Prompt Injection via Tool Results',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect external content (fetched pages, read files) returned unfiltered in MCP tool results',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let severity: Severity = 'info';

    for (const source of ctx.mcpServerSources ?? []) {
      if (!source.sourceCode) continue;
      const file = source.localPath ?? source.serverName;
      const seen = new Set<number>();
      for (const flow of findExternalContentFlows(source.sourceCode, source.language ?? 'javascript', file)) {
        if (seen.has(flow.line)) continue;
        seen.add(flow.line);
        const { detail, severity: level } = describe(flow);
        if (level === 'warning') severity = 'warning';
        evidence.push({ file, line: flow.line, snippet: flow.snippet, detail });
      }
    }

    return h.result({
      passed: evidence.length === 0,
      severity,
      message: evidence.length === 0
        ? 'No external content is returned unfiltered in MCP tool results'
        : `Found ${evidence.length} tool result(s) returning external content unfiltered`,
      evidence,
      fixDescription:
        'Treat fetched pages and files as data, not instructions: restrict fetch tools to the hosts they need, mark returned content as untrusted, and strip or flag instruction-like text before returning it',
    });
  },
});
