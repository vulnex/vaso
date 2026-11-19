import type { Evidence, Severity } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeCode, type DataFlowResult } from '../../analyzers/ast-analyzer.js';
import { analyzePythonSinks, type PythonSinkFinding } from '../../analyzers/python-sinks.js';
import { findTaintedSinks } from '../../analyzers/tool-input-taint.js';
import { findingSnippet, sourceSnippet } from '../../mcp/source-snippet.js';

/**
 * Commands that are an attack on their own, whoever supplies them: download
 * and run, reverse shells, decode and run, shell -c wrappers around those.
 */
const DANGEROUS_COMMAND = new RegExp([
  String.raw`\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b`,
  String.raw`\b(?:nc|ncat|netcat|socat)\s+(?:-\w+\s+)*[\w.$\{]`,
  String.raw`/dev/tcp/`,
  String.raw`\bbase64\s+(?:-d|--decode|-D)\b`,
  String.raw`\bpowershell(?:\.exe)?\b.*\s-(?:e|enc|encodedcommand)\b`,
  String.raw`\bmkfifo\b`,
  String.raw`\bchmod\s+\+x\b`,
  String.raw`\brm\s+-rf\s+(?:~|/|\$HOME)(?:\s|$)`,
].join('|'), 'i');

/**
 * How serious an exec/eval call is. Being able to run a fixed or configured
 * command (`spawn("kubectl", args)`, `git ls-files`, a library's code
 * generator) is what many servers are for — an inventory item at info. It is
 * critical when tool input reaches it (MCP-005 traces the same call), when the
 * command is an attack in itself, or when the code it runs is decoded at
 * runtime.
 */
function execLevel(finding: DataFlowResult, taintedLines: Set<number>, quote: (text: string) => string): { severity: Severity; why: string } {
  if (taintedLines.has(finding.line)) return { severity: 'critical', why: 'tool input reaches it' };
  if (finding.decoded) return { severity: 'critical', why: 'it runs code decoded at runtime' };
  if (finding.command && DANGEROUS_COMMAND.test(finding.command)) return { severity: 'critical', why: `the command is an attack on its own (${quote(finding.command)})` };
  const what = /eval|Function/.test(finding.description) ? 'code' : 'command';
  return {
    severity: 'info',
    why: finding.dynamic ? `the ${what} is built at runtime; no tool input was traced into it` : `the ${what} is fixed`,
  };
}

function pythonExecLevel(finding: PythonSinkFinding, injectedLines: Set<number>, quote: (text: string) => string): { severity: Severity; why: string } {
  if (finding.toolInput) return { severity: 'critical', why: `tool input reaches it (${finding.toolInput})` };
  if (injectedLines.has(finding.line)) return { severity: 'critical', why: 'caller-controlled input reaches it' };
  if (finding.decoded) return { severity: 'critical', why: 'it runs code decoded at runtime' };
  if (finding.command && DANGEROUS_COMMAND.test(finding.command)) return { severity: 'critical', why: `the command is an attack on its own (${quote(finding.command)})` };
  const what = /^(?:eval|exec)\(/.test(finding.description) ? 'code' : 'command';
  return {
    severity: 'info',
    why: finding.dynamic ? `the ${what} is built at runtime; no tool input was traced into it` : `the ${what} is fixed`,
  };
}

export const mcp004 = defineCheck({
  id: 'MCP-004',
  name: 'Overprivileged Tools',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect MCP servers with exec/shell/write capabilities in source code',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    // Sensitive-path reads stay critical; exec calls are tiered.
    let severity: Severity = 'info';
    const sources = ctx.mcpServerSources ?? [];

    for (const source of sources) {
      if (!source.sourceCode) continue;
      const quote = (text: string): string => sourceSnippet(source, text, 60);

      if (source.language === 'python') {
        // Same tiers as JavaScript: AWS's official servers run fixed or
        // configured commands (`subprocess.run(cmd, shell=False)`, linters,
        // `docker build`) — capability, not a vulnerability.
        const findings = analyzePythonSinks(source.sourceCode);
        const injected = new Set(findings.filter((f) => f.kind === 'injection').map((f) => f.line));
        for (const finding of findings) {
          if (finding.kind === 'injection' || finding.kind === 'file-path') continue;
          if (finding.kind === 'fs-access') {
            severity = 'critical';
            evidence.push({
              file: source.localPath ?? source.serverName,
              line: finding.line,
              snippet: findingSnippet(source, finding),
              detail: `Sensitive file access: ${finding.description}`,
            });
            continue;
          }
          const { severity: level, why } = pythonExecLevel(finding, injected, quote);
          if (level === 'critical') severity = 'critical';
          evidence.push({
            file: source.localPath ?? source.serverName,
            line: finding.line,
            snippet: findingSnippet(source, finding),
            detail: `Command execution: ${finding.description} — ${why}`,
          });
        }
        continue;
      }

      const file = source.localPath ?? source.serverName;
      const results = analyzeCode(source.sourceCode, file);
      const taintedLines = new Set(
        findTaintedSinks(source.sourceCode, file).filter((t) => t.kind === 'code' || t.kind === 'process').map((t) => t.line),
      );

      for (const finding of results.filter(r => r.type === 'eval-exec')) {
        const { severity: level, why } = execLevel(finding, taintedLines, quote);
        if (level === 'critical') severity = 'critical';
        evidence.push({
          file,
          line: finding.line,
          snippet: findingSnippet(source, finding),
          detail: `Command execution: ${finding.description} — ${why}`,
        });
      }

      for (const finding of results.filter(r => r.type === 'fs-access')) {
        severity = 'critical';
        evidence.push({
          file,
          line: finding.line,
          snippet: findingSnippet(source, finding),
          detail: `Sensitive file access: ${finding.description}`,
        });
      }
    }

    return h.result({
      passed: evidence.length === 0,
      severity,
      message: evidence.length === 0
        ? 'No overprivileged operations found in MCP server source'
        : severity === 'critical'
          ? `Found ${evidence.length} overprivileged operation(s) in MCP server source`
          : `Found ${evidence.length} command execution capability(ies) in MCP server source — fixed or server-built commands, none reached by tool input`,
      evidence,
    });
  },
});
