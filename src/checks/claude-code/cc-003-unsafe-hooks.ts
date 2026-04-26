import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const UNQUOTED_VAR_PATTERN = /(?<!["'])\$(?:CLAUDE_[A-Z_]+|TOOL_INPUT|USER_PROMPT|FILE_PATH|\{[A-Z_]+\})(?!["'])/;
const COMMAND_SUBSTITUTION_PATTERN = /\$\([^)]*\$[A-Z]/;
const RAW_EVAL_PATTERN = /\b(?:eval|bash\s+-c|sh\s+-c|exec)\b/;

interface HookEntry {
  matcher?: string;
  hooks?: Array<{ type?: string; command?: string }>;
}

export const cc003: CheckModule = {
  id: 'CC-003',
  name: 'Unsafe Hook Commands',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Claude Code hooks that exec untrusted shell input without quoting',
  supportedAgents: ['claude-code'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const hooks = config.data.hooks as Record<string, unknown> | undefined;
      if (!hooks || typeof hooks !== 'object') continue;

      for (const [event, entries] of Object.entries(hooks)) {
        if (!Array.isArray(entries)) continue;
        for (const entry of entries as HookEntry[]) {
          const hookList = Array.isArray(entry?.hooks) ? entry.hooks : [];
          for (const hook of hookList) {
            const cmd = hook?.command;
            if (typeof cmd !== 'string') continue;

            const reasons: string[] = [];
            if (UNQUOTED_VAR_PATTERN.test(cmd)) {
              reasons.push('uses unquoted $-variables that could expand into a shell injection');
            }
            if (COMMAND_SUBSTITUTION_PATTERN.test(cmd)) {
              reasons.push('embeds variables inside command substitution');
            }
            if (RAW_EVAL_PATTERN.test(cmd)) {
              reasons.push('invokes eval/sh -c/bash -c on dynamic input');
            }

            if (reasons.length > 0) {
              evidence.push({
                file: config.filePath,
                snippet: `${event}${entry.matcher ? `(${entry.matcher})` : ''}: ${cmd.slice(0, 120)}`,
                detail: reasons.join('; '),
              });
            }
          }
        }
      }
    }

    return {
      id: 'CC-003',
      name: 'Unsafe Hook Commands',
      category: 'coding-agent',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No unsafe hook commands detected'
        : `Found ${evidence.length} hook command(s) that may execute untrusted input`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Quote $-variables ("$VAR") and avoid eval/sh -c with dynamic input',
    };
  },
};
