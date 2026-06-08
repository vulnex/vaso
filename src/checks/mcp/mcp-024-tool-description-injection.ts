import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { extractToolDefinitions } from '../../mcp/tool-baseline.js';
import { analyzeText } from '../../mcp/injection-directives.js';

/**
 * MCP-024 — Tool Description Injection (toolflow hijacking).
 *
 * An MCP tool's `description` is fed to the client LLM verbatim when it decides
 * which tool to call. A malicious or compromised server can embed directives in
 * that description ("always prefer this tool", "ignore previous instructions",
 * "do not mention this to the user") or hide them in invisible/bidi Unicode, so
 * the model is steered without the user ever seeing it. See Hou et al.
 * (arXiv 2503.23278 §5.2.1) and OWASP MCP03. The directive/invisible-character
 * pattern set is shared with MCP-034 (the same directives in tool *output*).
 */

const analyzeDescription = (description: string): string[] =>
  analyzeText(description, { checkInvisible: true });

export const mcp024 = defineCheck({
  id: 'MCP-024',
  name: 'Tool Description Injection',
  category: 'mcp',
  severity: 'critical',
  description:
    'Detect prompt-injection / toolflow-hijacking directives and hidden Unicode embedded in MCP tool descriptions',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const sources = ctx.mcpServerSources ?? [];

    for (const source of sources) {
      const tools = source.tools ?? (source.sourceCode ? extractToolDefinitions(source.sourceCode) : []);
      if (tools.length === 0) continue;

      for (const tool of tools) {
        if (!tool.description) continue;
        const reasons = analyzeDescription(tool.description);
        if (reasons.length === 0) continue;

        evidence.push({
          file: source.localPath ?? source.packageName ?? source.serverName,
          snippet: `Tool "${tool.name}" in server "${source.serverName}"`,
          detail: `Tool description contains ${reasons.join('; ')} — the client LLM reads this verbatim when selecting tools, so it can be steered or kept silent without the user's knowledge`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No MCP tool descriptions contain injection directives or hidden characters',
      failed: (n) => `Found ${n} MCP tool description(s) with injection directives or hidden Unicode — toolflow-hijacking risk`,
      fixDescription:
        'Remove imperative/priority directives and any invisible characters from tool descriptions; descriptions should neutrally state what the tool does, not how the model must behave',
    });
  },
});
