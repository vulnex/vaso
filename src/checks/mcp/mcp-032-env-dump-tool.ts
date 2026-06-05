import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

/**
 * MCP-032 — Environment-Dump Tool.
 *
 * A server tool that returns the whole process environment (a `printEnv`-style
 * tool, `JSON.stringify(process.env)`, `{...process.env}`) hands every secret in
 * the agent's environment to the model — and thence to anything that can read a
 * tool result. This is the Credential-Theft path in arXiv 2504.03767 (a literal
 * `printEnv` tool) and SlowMist checklist item 18. Reading a *specific* variable
 * (`process.env.API_BASE`) is fine and not flagged.
 */

interface DumpPattern {
  re: RegExp;
  label: string;
}

const DUMP_PATTERNS: DumpPattern[] = [
  // Whole `process.env` object referenced (not `process.env.SPECIFIC` / `[...]`).
  { re: /process\.env(?!\s*\.\s*[A-Za-z_$])(?!\s*\[)/, label: 'returns/serializes the whole process.env' },
  // Python servers (source may be resolved locally).
  { re: /\bos\.environ(?!\s*\.\s*get)(?!\s*\[)/, label: 'returns the whole os.environ' },
  { re: /\bdict\(\s*os\.environ\s*\)/, label: 'serializes os.environ' },
  // Shell environment dump.
  { re: /\b(printenv|\/usr\/bin\/env|\benv\b\s*\|)/, label: 'runs a shell environment dump (printenv/env)' },
];

export const mcp032 = defineCheck({
  id: 'MCP-032',
  name: 'Environment-Dump Tool',
  category: 'mcp',
  severity: 'warning',
  description:
    'Detect MCP server tools that return the entire process environment (printEnv-style credential exposure)',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const source of ctx.mcpServerSources ?? []) {
      if (!source.sourceCode) continue;

      const reasons = new Set<string>();
      for (const { re, label } of DUMP_PATTERNS) {
        if (re.test(source.sourceCode)) reasons.add(label);
      }
      if (reasons.size === 0) continue;

      evidence.push({
        file: source.localPath ?? source.packageName ?? source.serverName,
        snippet: `Server "${source.serverName}"`,
        detail: `MCP server source ${[...reasons].join('; ')} — exposing the full environment leaks every secret the agent holds to the model and tool-result consumers`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'No MCP server tools dump the full process environment',
      failed: (n) => `Found ${n} MCP server(s) exposing the full process environment`,
      fixDescription:
        'Return only the specific environment values a tool needs (e.g. process.env.API_BASE), never the whole environment object',
    });
  },
});
