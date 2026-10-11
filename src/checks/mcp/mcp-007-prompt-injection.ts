import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { sourceSegments, segmentSnippet } from '../../mcp/source-segments.js';

// Patterns indicating raw external content returned unsanitized in tool results
const UNSAFE_RETURN_PATTERNS = [
  // A fetch() result is a Response object; it becomes content once its body is
  // read. `return await fetch(tokenEndpoint, …)` in an OAuth helper is not a
  // tool result.
  { pattern: /return\s+(?:await\s+)?\(?\s*(?:await\s+)?(?:fetch|axios|got|request)\s*\(.*\)\s*\)?\s*\.(?:text|json)\s*\(/, name: 'Raw HTTP response returned as tool result' },
  { pattern: /return\s+(?:await\s+)?(?:readFile|readFileSync)\s*\(/, name: 'Raw file content returned as tool result' },
  { pattern: /content\s*:\s*(?:await\s+)?(?:fetch|response|res)\b/, name: 'External content injected into tool result' },
  { pattern: /tool_result.*(?:fetch|http|request)/i, name: 'External fetch in tool result handler' },
  { pattern: /innerHTML|outerHTML|document\.write/i, name: 'DOM manipulation from external content' },
];

// Patterns indicating sanitization is present (reduce false positives)
const SANITIZATION_PATTERNS = [
  /sanitize|escape|encode|strip|clean|purify|validate/i,
  /DOMPurify|xss|helmet/i,
  /\.replace\(.*<.*>/i,
];

export const mcp007 = defineCheck({
  id: 'MCP-007',
  name: 'Prompt Injection via Tool Results',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect raw external content returned unsanitized in MCP tool results',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const sources = ctx.mcpServerSources ?? [];

    for (const source of sources) {
      if (!source.sourceCode) continue;

      // Check if the source has any sanitization
      const hasSanitization = SANITIZATION_PATTERNS.some(p => p.test(source.sourceCode!));

      for (const segment of sourceSegments(source.sourceCode)) {
        for (const { pattern, name } of UNSAFE_RETURN_PATTERNS) {
          if (pattern.test(segment.text)) {
            evidence.push({
              file: source.localPath ?? source.serverName,
              line: segment.line,
              snippet: segmentSnippet(segment),
              detail: hasSanitization
                ? `${name} (sanitization detected elsewhere — verify coverage)`
                : `${name} (no sanitization detected)`,
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No prompt injection risks detected in MCP tool results',
      failed: (n) => `Found ${n} potential prompt injection vector(s) in MCP tool results`,
    });
  },
});
