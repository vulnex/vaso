import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { confinesPaths, findTaintedSinks, literalOnlyNames } from '../../analyzers/tool-input-taint.js';
import { analyzePythonSinks } from '../../analyzers/python-sinks.js';
import { sourceSegments, segmentSnippet } from '../../mcp/source-segments.js';

const INPUT_NAMES = 'req|input|args|params|query|body|tool_input|message';
const INPUT = String.raw`(?:${INPUT_NAMES})\b`;

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
  // The string runs to its own closing quote: f"… WHERE name = '{name}'" quotes the value inside.
  { pattern: /\.execute(?:many)?\s*\(\s*(?:f(["'])(?:(?!\1).){0,500}?\b(?:SELECT|INSERT|UPDATE|DELETE)\b(?:(?!\1).){0,500}?\{|(["'])(?:(?!\2).){0,500}?\b(?:SELECT|INSERT|UPDATE|DELETE)\b(?:(?!\2).){0,500}?\2\s*(?:%|\+|\.format\())/i, name: 'SQL injection via string formatting' },
  // The fs call itself (`fs.writeFile(args…`), not a function named for it (`handleWriteFile(args)`).
  { pattern: new RegExp(String.raw`(?<![\w$])writeFile(?:Sync)?\s*\(\s*` + INPUT), name: 'File write with user-controlled path' },
];

/**
 * The SQL patterns go by what a value is called (`${query}`, `+ body.id`);
 * a name the file only ever binds to a literal (`const query = "orders"`)
 * holds no input, whatever it is called.
 */
function interpolatesOnlyConstants(statement: string, constants: () => Set<string>): boolean {
  const roots = [...statement.matchAll(new RegExp(String.raw`(?:\$\{\s*|\+\s*)(${INPUT_NAMES})(?![\w$])`, 'g'))].map(m => m[1]);
  return roots.length > 0 && roots.every(r => constants().has(r));
}

/**
 * An f-string query whose every interpolated name was assigned from a
 * validator (`table = validate_identifier(parts[0])`, `sanitize_*`, `quote_*`,
 * an allowlist lookup) builds SQL from checked identifiers, not from raw input.
 */
function interpolatesOnlyValidated(statement: string, source: string): boolean {
  const names = [...statement.matchAll(/\{([A-Za-z_]\w*)\}/g)].map(m => m[1]);
  if (names.length === 0) return false;
  return names.every(n => new RegExp(String.raw`\b${n}\s*=\s*[\w.]*(?:valid|saniti[sz]|escape|quote|allow(?:ed|list)|whitelist)\w*\s*\(`, 'i').test(source));
}

/**
 * Every input-named interpolation in the statement stands for a whole
 * statement, not a value: a derived table (`SELECT TOP ${n} * FROM (${body}) AS subq`,
 * `JOIN (${q})`), a CTE body (`WITH t AS (${sql})`) or an `EXPLAIN ${query}`.
 * That is the server wrapping a query to cap or inspect it.
 */
function wrapsWholeStatement(statement: string): boolean {
  const uses = [...statement.matchAll(new RegExp(String.raw`\$\{\s*(?:${INPUT_NAMES})(?![\w$])[^}]*\}`, 'g'))];
  return uses.length > 0 && uses.every((m) => {
    const before = statement.slice(Math.max(0, m.index - 60), m.index);
    const after = statement.slice(m.index + m[0].length, m.index + m[0].length + 20);
    // the closing paren may be on the next line (a segment is one line)
    return (/\b(?:FROM|JOIN|AS)\s*\(\s*$/i.test(before) && /^\s*(?:\)|$)/.test(after)) || /\bEXPLAIN(?:\s+[A-Z]+)*\s+$/i.test(before);
  });
}

/**
 * The server has a tool whose job is running the caller's SQL (dbhub's
 * `execute_sql`, `run_query`, an input field named `sql`): wrapping that query
 * gives the caller nothing they don't already have.
 */
function runsCallerSql(source: string): boolean {
  return /["'`](?:execute|run|exec)[_-]?(?:sql|query)\w*["'`]|\bsql\s*:\s*z\s*\.\s*string\s*\(|["']sql["']\s*:\s*\{\s*["']?type["']?\s*:\s*["']string["']/i.test(source);
}

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
          if (sink.kind === 'query') {
            // Wrapping the caller's whole statement (a derived table, EXPLAIN)
            // in a server whose tool runs the caller's SQL gives nothing new
            const wraps = sink.wrapsStatement === true && runsCallerSql(source.sourceCode);
            evidence.push({
              file,
              line: sink.line,
              snippet: sink.snippet,
              detail: wraps
                ? `SQL injection via template literal: ${sink.sink}() wraps a whole query from tool input (${sink.origin}) in a server with a tool that runs the caller's SQL — the caller already chooses the statement`
                : `${sink.sink}() builds SQL text from tool input (${sink.origin}) — SQL injection; pass values as bound parameters`,
              ...(wraps ? { mitigated: true } : {}),
            });
            continue;
          }
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

      let constants: Set<string> | undefined;
      let sqlTool: boolean | undefined;
      const constantNames = () => (constants ??= source.language === 'python' ? new Set() : literalOnlyNames(source.sourceCode!));
      for (const segment of sourceSegments(source.sourceCode)) {
        if (reported.has(segment.line)) continue;
        for (const { pattern, name } of INJECTION_PATTERNS) {
          if (pattern.test(segment.text)) {
            if (name === 'SQL injection via string formatting' && interpolatesOnlyValidated(segment.text, source.sourceCode)) continue;
            if (name.startsWith('SQL injection via') && interpolatesOnlyConstants(segment.text, constantNames)) continue;
            reported.add(segment.line);
            if (name === 'SQL injection via template literal' && wrapsWholeStatement(segment.text) && (sqlTool ??= runsCallerSql(source.sourceCode))) {
              evidence.push({
                file, line: segment.line, snippet: segmentSnippet(segment), mitigated: true,
                detail: `${name}: the template wraps a whole query (derived table, CTE or EXPLAIN) in a server with a tool that runs the caller's SQL — the caller already chooses the statement`,
              });
              break;
            }
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
