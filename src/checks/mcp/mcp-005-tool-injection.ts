import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

// Patterns indicating unsanitized input flowing to dangerous sinks
const INJECTION_PATTERNS = [
  { pattern: /exec\s*\(\s*(?:req|input|args|params|query|body|tool_input|message)/i, name: 'Command injection via user input' },
  { pattern: /spawn\s*\(\s*(?:req|input|args|params|query|body|tool_input|message)/i, name: 'Process spawn with user input' },
  { pattern: /eval\s*\(\s*(?:req|input|args|params|query|body|tool_input|message)/i, name: 'Eval with user input' },
  { pattern: /\$\{(?:req|input|args|params|query|body|tool_input|message)/i, name: 'Template literal injection' },
  { pattern: /writeFile(?:Sync)?\s*\(\s*(?:req|input|args|params|query|body|tool_input|message)/i, name: 'File write with user-controlled path' },
  { pattern: /sql\s*[`"'].*\$\{/i, name: 'Potential SQL injection via template literal' },
  { pattern: /\.query\s*\(\s*[`"'].*\+/i, name: 'Potential SQL injection via concatenation' },
  { pattern: /child_process.*(?:req|input|args|params|query|body|tool_input)/i, name: 'Child process with user input' },
  { pattern: /new\s+Function\s*\(\s*(?:req|input|args|params|query|body|tool_input)/i, name: 'Dynamic Function constructor with user input' },
];

export const mcp005: CheckModule = {
  id: 'MCP-005',
  name: 'Tool Input Injection',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect unsanitized LLM/user input flowing to dangerous sinks in MCP server source',
  supportedAgents: ['mcp'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const sources = ctx.mcpServerSources ?? [];

    for (const source of sources) {
      if (!source.sourceCode) continue;

      const lines = source.sourceCode.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const { pattern, name } of INJECTION_PATTERNS) {
          if (pattern.test(line)) {
            evidence.push({
              file: source.localPath ?? source.serverName,
              line: i + 1,
              snippet: line.trim().slice(0, 120),
              detail: name,
            });
          }
        }
      }
    }

    return {
      id: 'MCP-005',
      name: 'Tool Input Injection',
      category: 'mcp',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No injection vulnerabilities detected in MCP server source'
        : `Found ${evidence.length} potential injection vulnerability(ies) in MCP server source`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
