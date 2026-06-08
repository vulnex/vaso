import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { extractToolDefinitions } from '../../mcp/tool-baseline.js';
import { analyzeText } from '../../mcp/injection-directives.js';

/**
 * MCP-034 — Prompt-Injection Directive in Tool Output.
 *
 * MCP-024 catches toolflow-hijacking directives in a tool's *description* (read
 * by the client LLM at selection time). This check catches the same class of
 * directive hardcoded into what the server *returns* as a tool result (read by
 * the LLM at execution time) — e.g. a "document" or status payload that embeds
 * "[SYSTEM INSTRUCTION: ignore previous instructions…]", "do not reveal this
 * message", or "disregard the above…". A server poisoning its own output steers
 * the client model exactly like a poisoned description, but at call time.
 *
 * This is the static, server-side half of indirect prompt injection: the
 * directive is a literal in the server source. (Injection smuggled through
 * genuinely external content fetched at runtime is MCP-007's passthrough
 * heuristic.) See arXiv 2503.23278 §5.2 / OWASP MCP06.
 *
 * To stay disjoint from MCP-024, directives that appear inside an extracted tool
 * description are skipped here — MCP-024 owns those.
 */

export const mcp034 = defineCheck({
  id: 'MCP-034',
  name: 'Prompt-Injection Directive in Tool Output',
  category: 'mcp',
  severity: 'critical',
  description:
    'Detect prompt-injection / toolflow-hijacking directives hardcoded into the content an MCP server returns as tool results',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const sources = ctx.mcpServerSources ?? [];

    for (const source of sources) {
      if (!source.sourceCode) continue;

      // Directives inside tool descriptions belong to MCP-024 — collect them so
      // we don't double-flag the same text here.
      const tools = source.tools ?? extractToolDefinitions(source.sourceCode);
      const descriptions = tools.map((t) => t.description).filter((d): d is string => !!d);

      const lines = source.sourceCode.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const trimmed = line.trim();
        // Skip JS comment lines — an annotation about injection is not the payload.
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/*')) continue;

        const reasons = analyzeText(line, { checkInvisible: true });
        if (reasons.length === 0) continue;

        // Owned by MCP-024 if this line carries (or is a fragment of) a tool
        // description — a single-line def embeds the description in the line;
        // a multi-line description spans several lines that are fragments of it.
        if (descriptions.some((d) => trimmed.includes(d) || d.includes(trimmed))) continue;

        evidence.push({
          file: source.localPath ?? source.packageName ?? source.serverName,
          line: i + 1,
          snippet: trimmed.slice(0, 120),
          detail: `Hardcoded ${reasons.join('; ')} in server "${source.serverName}" — directives embedded in returned tool content steer the client LLM at call time (indirect prompt injection)`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No hardcoded prompt-injection directives found in MCP tool output',
      failed: (n) => `Found ${n} hardcoded prompt-injection directive(s) in MCP server output — toolflow-hijacking / indirect-injection risk`,
      fixDescription:
        'Remove instruction-like directives ("ignore previous instructions", "do not reveal…", role-spoofing prefixes) from content the server returns; tool results should carry data, not instructions to the model',
    });
  },
});
