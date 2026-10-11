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

/** Whole `process.env` (not `.KEY`, `[KEY]` or `?.KEY`). */
const WHOLE_PROCESS_ENV = /process\.env(?!\s*(?:\.|\[|\?\.))/g;

/**
 * Text right before a whole-`process.env` reference that makes it benign: a
 * membership test (`Object.hasOwn(process.env, k)`, `k in process.env`), or
 * handing the environment to a child process (`env: process.env`,
 * `env: { ...process.env, X }`, `const childEnv = { ...process.env }`) — the
 * child inherits it anyway; nothing reaches the model.
 */
const BENIGN_PROCESS_ENV_PREFIX = new RegExp(
  [
    String.raw`\b(?:hasOwn|hasOwnProperty(?:\.call)?|Reflect\.has)\s*\(\s*$`,
    String.raw`\bin\s+$`,
    // `env:` option of a child process — directly, spread, or one branch of a
    // ternary; no call in between (`env: JSON.stringify(process.env)` is not).
    String.raw`\benv\s*:[^;{}()]*(?:\{\s*(?:[^{}()]*,\s*)?\.\.\.\s*)?$`,
    // An env-named variable taking the environment (or a fallback/spread of it).
    String.raw`\b\w*[eE]nv\w*\s*=\s*(?:[^;=(){}]*(?:\?\?|\|\||\?|:)\s*)?(?:\{\s*(?:[^{}()]*,\s*)?\.\.\.\s*)?$`,
  ].join('|'),
);

/** `fn(` immediately before the reference — process.env is a call argument. */
const CALL_ARGUMENT = /([A-Za-z_$][\w$.]*)\s*\(\s*$/;
/** Calls that serialize or enumerate the whole environment. */
const DUMPING_CALLEES = /(?:^|\.)(?:stringify|inspect|String|entries|keys|values)$/;
/** A default parameter: `function f(environment = process.env)`. */
const DEFAULT_PARAMETER = /[(,]\s*[A-Za-z_$][\w$]*\s*=\s*$/;

interface DumpPattern {
  re: RegExp;
  label: string;
}

const LINE_PATTERNS: DumpPattern[] = [
  // Python: the whole os.environ handed to a serializer or returned.
  {
    re: /\b(?:json\.dumps|str|repr|pformat|jsonify)\s*\(\s*(?:dict\(\s*)?os\.environ\b(?!\s*(?:\.\s*get\b|\[))/,
    label: 'serializes the whole os.environ',
  },
  {
    re: /\breturn\s+(?:dict\(\s*|\{\s*\*\*\s*)?os\.environ\b(?!\s*(?:\.\s*get\b|\[))/,
    label: 'returns the whole os.environ',
  },
  { re: /\{\s*os\.environ\s*\}/, label: 'formats the whole os.environ into a string' },
  // Shell environment dump: `printenv` with no variable name, or `env` alone / piped.
  { re: /\bprintenv\b(?!\s+[A-Za-z_$])/, label: 'runs a shell environment dump (printenv/env)' },
  {
    re: /\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|system|popen|check_output|run|call|Popen|create_subprocess_(?:exec|shell))\s*\(\s*\[?\s*["'`](?:\/usr\/bin\/)?env["'`]/,
    label: 'runs a shell environment dump (printenv/env)',
  },
  { re: /["'`][^"'`\n]*?\benv\s*\|(?!\|)/, label: 'runs a shell environment dump (printenv/env)' },
];

function isCommentLine(line: string): boolean {
  const t = line.trimStart();
  return t.startsWith('//') || t.startsWith('*') || t.startsWith('#');
}

/** Reasons the source exposes the whole environment, deduplicated. */
function dumpReasons(code: string): Set<string> {
  const reasons = new Set<string>();

  for (const m of code.matchAll(WHOLE_PROCESS_ENV)) {
    const lineStart = code.lastIndexOf('\n', m.index) + 1;
    if (isCommentLine(code.slice(lineStart, m.index))) continue;
    const before = code.slice(Math.max(0, m.index - 160), m.index).replace(/\s+/g, ' ');
    if (BENIGN_PROCESS_ENV_PREFIX.test(before) || DEFAULT_PARAMETER.test(before)) continue;
    const callee = CALL_ARGUMENT.exec(before)?.[1];
    if (callee) {
      // Handed to a config reader / loader: it reads keys, it doesn't dump.
      if (!DUMPING_CALLEES.test(callee)) continue;
      // `Object.keys(process.env).filter(…)` or a loop that keeps only names
      // with its own prefix picks its own variables (the `debug` package does
      // this in nearly every bundle).
      const after = code.slice(m.index + m[0].length, m.index + m[0].length + 120).split(';')[0];
      if (/(?:entries|keys)$/.test(callee) && /\.\s*filter\s*\(|startsWith\s*\(|\.test\s*\(|\.match\s*\(/.test(after)) continue;
    }
    reasons.add('returns/serializes the whole process.env');
    break;
  }

  for (const line of code.split('\n')) {
    if (isCommentLine(line)) continue;
    for (const { re, label } of LINE_PATTERNS) {
      if (re.test(line)) reasons.add(label);
    }
  }
  return reasons;
}

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

      const reasons = dumpReasons(source.sourceCode);
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
