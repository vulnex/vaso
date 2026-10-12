import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { confinesPaths, findTaintedSinks } from '../../analyzers/tool-input-taint.js';
import { analyzePythonSinks } from '../../analyzers/python-sinks.js';
import { sourceSegments, segmentSnippet } from '../../mcp/source-segments.js';

const INPUT = String.raw`(?:req|input|args|params|query|body|tool_input|message)\b`;

/**
 * Query and file-write sinks that take tool input, matched per statement.
 * Code and command sinks (eval, Function, vm, child_process; Python exec,
 * subprocess, os.system) are traced through variables by findTaintedSinks /
 * analyzePythonSinks — a line regex for those misfired on every bundled module
 * that mentions child_process near a variable named `args`.
 */
const INJECTION_PATTERNS = [
  // A template builds a query only when it holds SQL; error/log messages that
  // interpolate `request.params.name` are not injection. Tagged templates
  // (sql`… ${id}`) are parameterized by the library and safe.
  { pattern: new RegExp(String.raw`(?<!\w)\`[^\`]*\b(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^\`]*\$\{\s*` + INPUT), name: 'SQL injection via template literal' },
  { pattern: new RegExp(String.raw`\.(?:query|execute|raw)\s*\(\s*["'\`][^"'\`]*["'\`]\s*\+\s*` + INPUT), name: 'SQL injection via concatenation' },
  // Python DB-API: f-string, %-format or concatenation into execute().
  { pattern: /\.execute(?:many)?\s*\(\s*(?:f["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*\{|["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*(?:%|\+|\.format\())/i, name: 'SQL injection via string formatting' },
  { pattern: new RegExp(String.raw`writeFile(?:Sync)?\s*\(\s*` + INPUT, 'i'), name: 'File write with user-controlled path' },
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
        // Tool input traced through variables into eval/Function/vm/child_process,
        // and into the path of a file read or write when nothing confines it to
        // a base directory (listing/stat-only paths are MCP-009's).
        const confined = confinesPaths(source.sourceCode);
        for (const sink of findTaintedSinks(source.sourceCode, file)) {
          if (reported.has(sink.line) || sink.kind === 'file-meta') continue;
          const fileSink = sink.kind === 'file-read' || sink.kind === 'file-write';
          if (fileSink && confined) continue;
          reported.add(sink.line);
          evidence.push({
            file,
            line: sink.line,
            snippet: sink.snippet,
            detail: fileSink
              ? `${sink.sink}() ${sink.kind === 'file-read' ? 'reads' : 'writes'} a path taken from tool input (${sink.origin}) with no containment check — the caller can ${sink.kind === 'file-read' ? 'read' : 'write'} any file the server can (path traversal)`
              : `${sink.sink}() receives tool input (${sink.origin})`,
          });
        }
      }

      for (const segment of sourceSegments(source.sourceCode)) {
        if (reported.has(segment.line)) continue;
        for (const { pattern, name } of INJECTION_PATTERNS) {
          if (pattern.test(segment.text)) {
            reported.add(segment.line);
            evidence.push({ file, line: segment.line, snippet: segmentSnippet(segment), detail: name });
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
