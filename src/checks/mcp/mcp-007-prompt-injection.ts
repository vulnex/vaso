import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

// Patterns indicating raw external content returned unsanitized in tool results
const UNSAFE_RETURN_PATTERNS = [
  { pattern: /return\s+(?:await\s+)?(?:fetch|axios|got|request)\s*\(/, name: 'Raw HTTP response returned as tool result' },
  { pattern: /return\s+(?:await\s+)?(?:readFile|readFileSync)\s*\(/, name: 'Raw file content returned as tool result' },
  { pattern: /return\s+(?:await\s+)?(?:\.text\(\)|\.json\(\)|\.body)/, name: 'Raw response body returned as tool result' },
  { pattern: /content\s*:\s*(?:await\s+)?(?:fetch|response|res)/, name: 'External content injected into tool result' },
  { pattern: /tool_result.*(?:fetch|http|request)/i, name: 'External fetch in tool result handler' },
  { pattern: /innerHTML|outerHTML|document\.write/i, name: 'DOM manipulation from external content' },
];

// Patterns indicating sanitization is present (reduce false positives)
const SANITIZATION_PATTERNS = [
  /sanitize|escape|encode|strip|clean|purify|validate/i,
  /DOMPurify|xss|helmet/i,
  /\.replace\(.*<.*>/i,
];

export const mcp007: CheckModule = {
  id: 'MCP-007',
  name: 'Prompt Injection via Tool Results',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect raw external content returned unsanitized in MCP tool results',
  supportedAgents: ['mcp'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const sources = ctx.mcpServerSources ?? [];

    for (const source of sources) {
      if (!source.sourceCode) continue;

      // Check if the source has any sanitization
      const hasSanitization = SANITIZATION_PATTERNS.some(p => p.test(source.sourceCode!));

      const lines = source.sourceCode.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const { pattern, name } of UNSAFE_RETURN_PATTERNS) {
          if (pattern.test(line)) {
            evidence.push({
              file: source.localPath ?? source.serverName,
              line: i + 1,
              snippet: line.trim().slice(0, 120),
              detail: hasSanitization
                ? `${name} (sanitization detected elsewhere — verify coverage)`
                : `${name} (no sanitization detected)`,
            });
          }
        }
      }
    }

    return {
      id: 'MCP-007',
      name: 'Prompt Injection via Tool Results',
      category: 'mcp',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No prompt injection risks detected in MCP tool results'
        : `Found ${evidence.length} potential prompt injection vector(s) in MCP tool results`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
