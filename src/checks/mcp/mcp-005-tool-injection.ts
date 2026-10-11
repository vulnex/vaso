import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { findTaintedSinks } from '../../analyzers/tool-input-taint.js';
import { analyzePythonSinks } from '../../analyzers/python-sinks.js';

// Patterns indicating unsanitized input flowing to dangerous sinks
const INJECTION_PATTERNS = [
  { pattern: /exec\s*\(\s*(?:req|input|args|params|query|body|tool_input|message)/i, name: 'Command injection via user input' },
  { pattern: /spawn\s*\(\s*(?:req|input|args|params|query|body|tool_input|message)/i, name: 'Process spawn with user input' },
  { pattern: /eval\s*\(\s*(?:req|input|args|params|query|body|tool_input|message)/i, name: 'Eval with user input' },
  // A template only matters when it builds a query; error/log messages that
  // interpolate `request.params.name` are not injection. Code and command
  // sinks reached through templates are traced by findTaintedSinks.
  { pattern: /`[^`]*\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^`]*\$\{\s*(?:req|input|args|params|query|body|tool_input|message)\b/, name: 'SQL injection via template literal' },
  { pattern: /writeFile(?:Sync)?\s*\(\s*(?:req|input|args|params|query|body|tool_input|message)/i, name: 'File write with user-controlled path' },
  { pattern: /sql\s*[`"'].*\$\{/i, name: 'Potential SQL injection via template literal' },
  { pattern: /\.query\s*\(\s*[`"'].*\+/i, name: 'Potential SQL injection via concatenation' },
  { pattern: /child_process.*(?:req|input|args|params|query|body|tool_input)/i, name: 'Child process with user input' },
  { pattern: /new\s+Function\s*\(\s*(?:req|input|args|params|query|body|tool_input)/i, name: 'Dynamic Function constructor with user input' },
];

export const mcp005 = defineCheck({
  id: 'MCP-005',
  name: 'Tool Input Injection',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect unsanitized LLM/user input flowing to dangerous sinks in MCP server source',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const sources = ctx.mcpServerSources ?? [];

    for (const source of sources) {
      if (!source.sourceCode) continue;
      const file = source.localPath ?? source.serverName;
      const reported = new Set<number>();

      if (source.language === 'python') {
        for (const finding of analyzePythonSinks(source.sourceCode)) {
          if (finding.kind !== 'injection' || reported.has(finding.line)) continue;
          reported.add(finding.line);
          evidence.push({ file, line: finding.line, snippet: finding.snippet, detail: finding.description });
        }
      } else {
        // Tool input traced through variables into eval/Function/vm/child_process.
        for (const sink of findTaintedSinks(source.sourceCode, file)) {
          if (reported.has(sink.line)) continue;
          reported.add(sink.line);
          evidence.push({
            file,
            line: sink.line,
            snippet: sink.snippet,
            detail: `${sink.sink}() receives tool input (${sink.origin})`,
          });
        }
      }

      const lines = source.sourceCode.split('\n');
      for (let i = 0; i < lines.length; i++) {
        if (reported.has(i + 1)) continue;
        const line = lines[i];
        const trimmed = line.trim();
        if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) continue;
        for (const { pattern, name } of INJECTION_PATTERNS) {
          if (pattern.test(line)) {
            reported.add(i + 1);
            evidence.push({
              file,
              line: i + 1,
              snippet: line.trim().slice(0, 120),
              detail: name,
            });
            break;
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No injection vulnerabilities detected in MCP server source',
      failed: (n) => `Found ${n} potential injection vulnerability(ies) in MCP server source`,
    });
  },
});
