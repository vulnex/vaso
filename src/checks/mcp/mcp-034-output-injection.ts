import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { extractToolDefinitions } from '../../mcp/tool-baseline.js';
import { analyzeText, isInvisibleCodePoint, describeChar, isWeakDirective } from '../../mcp/injection-directives.js';
import { stringLines } from '../../analyzers/string-literals.js';
import type { StringLine } from '../../analyzers/string-literals.js';

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
    let sawStrong = false;
    const sources = ctx.mcpServerSources ?? [];

    for (const source of sources) {
      if (!source.sourceCode) continue;
      const file = source.localPath ?? source.packageName ?? source.serverName;

      // Directives inside tool descriptions belong to MCP-024 — collect them so
      // we don't double-flag the same text here.
      const tools = source.tools ?? extractToolDefinitions(source.sourceCode);
      const descriptions = tools.map((t) => t.description).filter((d): d is string => !!d);

      // Judge string contents, not code: `system: prompt.system` is an object
      // key. Python (or unparseable source) falls back to non-comment lines.
      const units: StringLine[] =
        (source.language === 'python' ? undefined : stringLines(source.sourceCode)) ??
        commentFreeLines(source.sourceCode);

      const reported = new Set<number>();
      for (const unit of units) {
        if (unit.description || reported.has(unit.line)) continue;
        const trimmed = unit.text.trim();
        const reasons = analyzeText(unit.text);
        if (reasons.length === 0) continue;
        // Owned by MCP-024 if this text carries (or is a fragment of) an
        // extracted tool description.
        if (descriptions.some((d) => trimmed.includes(d) || d.includes(trimmed))) continue;

        reported.add(unit.line);
        const strong = reasons.some((r) => !isWeakDirective(r));
        if (strong) sawStrong = true;
        evidence.push({
          file,
          line: unit.line,
          snippet: trimmed.slice(0, 120),
          detail: strong
            ? `Hardcoded ${reasons.join('; ')} in server "${source.serverName}" — directives embedded in returned tool content steer the client LLM at call time (indirect prompt injection)`
            : `Instruction-like phrasing (${reasons.join('; ')}) in server "${source.serverName}" — weak signal on its own: common in error messages and prompts; review whether it reaches tool output`,
        });
      }

      // Text files the server loads and returns (RAG documents, canned
      // responses) carry directives just like literals in the code.
      for (const data of source.dataFiles ?? []) {
        const lines = data.content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const reasons = analyzeText(lines[i], { checkInvisible: true });
          if (reasons.length === 0) continue;
          const strong = reasons.some((r) => !isWeakDirective(r));
          if (strong) sawStrong = true;
          evidence.push({
            file: data.path,
            line: i + 1,
            snippet: lines[i].trim().slice(0, 120),
            detail: strong
              ? `${reasons.join('; ')} in a data file server "${source.serverName}" loads — content it returns as tool output steers the client LLM (indirect prompt injection)`
              : `Instruction-like phrasing (${reasons.join('; ')}) in a data file server "${source.serverName}" loads — weak signal on its own; review the content it returns`,
          });
        }
      }

      // Invisible / bidi characters can hide in code as well as strings.
      const lines = source.sourceCode.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (reported.has(i + 1)) continue;
        const invisible = new Set<string>();
        for (const ch of lines[i]) {
          const cp = ch.codePointAt(0) ?? 0;
          if (isInvisibleCodePoint(cp)) invisible.add(describeChar(cp));
        }
        if (invisible.size === 0) continue;
        sawStrong = true;
        evidence.push({
          file,
          line: i + 1,
          snippet: lines[i].trim().slice(0, 120),
          detail: `Hardcoded invisible/bidi characters (${[...invisible].join(', ')}) in server "${source.serverName}" — hidden text the client LLM reads but a reviewer cannot see`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      severity: sawStrong ? undefined : 'info',
      passed: 'No hardcoded prompt-injection directives found in MCP tool output',
      failed: (n) => `Found ${n} hardcoded prompt-injection directive(s) in MCP server output — toolflow-hijacking / indirect-injection risk`,
      fixDescription:
        'Remove instruction-like directives ("ignore previous instructions", "do not reveal…", role-spoofing prefixes) from content the server returns; tool results should carry data, not instructions to the model',
    });
  },
});

/** Fallback units: every non-comment line, as text. */
function commentFreeLines(code: string): StringLine[] {
  return code.split('\n').flatMap((text, i) => {
    const t = text.trim();
    if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*') || t.startsWith('#')) return [];
    return [{ line: i + 1, text, description: false }];
  });
}
