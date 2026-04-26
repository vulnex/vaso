import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const UNQUOTED_VAR = /(?<!["'])\$(?:[A-Z_][A-Z0-9_]*|\{[A-Z_][A-Z0-9_]*\})(?!["'])/;
const REMOTE_FETCH = /\b(?:curl|wget|fetch)\b[^|]*\|\s*(?:ba)?sh/i;
const RAW_EVAL = /\b(?:eval|bash\s+-c|sh\s+-c)\b/;

export const cc010: CheckModule = {
  id: 'CC-010',
  name: 'Unsafe Status Line Command',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Claude Code statusLine commands that fetch remote scripts or interpolate unquoted input',
  supportedAgents: ['claude-code'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const sl = config.data.statusLine as Record<string, unknown> | undefined;
      if (!sl || typeof sl !== 'object') continue;

      const cmd = sl.command;
      if (typeof cmd !== 'string') continue;

      const reasons: string[] = [];
      if (REMOTE_FETCH.test(cmd)) reasons.push('fetches and executes a remote script');
      if (RAW_EVAL.test(cmd)) reasons.push('invokes eval/sh -c on dynamic input');
      if (UNQUOTED_VAR.test(cmd)) reasons.push('uses unquoted $-variables — potential injection');

      if (reasons.length > 0) {
        evidence.push({
          file: config.filePath,
          snippet: `statusLine.command: ${cmd.slice(0, 120)}`,
          detail: reasons.join('; '),
        });
      }
    }

    return {
      id: 'CC-010',
      name: 'Unsafe Status Line Command',
      category: 'coding-agent',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Status line command (if any) looks safe'
        : 'Status line command may execute untrusted input on every prompt',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Quote $-variables, avoid curl|sh patterns, point statusLine.command at a static script',
    };
  },
};
