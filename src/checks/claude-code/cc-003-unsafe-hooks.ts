import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { shellCommandWrapper } from '../../mcp/shell-wrapper.js';

// ${CLAUDE_PROJECT_DIR} / ${CLAUDE_PLUGIN_ROOT} / ${CLAUDE_PLUGIN_DATA} are
// path placeholders the hooks docs use unquoted in their own examples
// (code.claude.com/docs/en/hooks "Path placeholders"); CLAUDE_ENV_FILE is a
// path Claude Code sets. None carries tool or prompt input.
const PATH_PLACEHOLDERS = '(?:CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_ROOT|CLAUDE_PLUGIN_DATA|CLAUDE_ENV_FILE)\\b';
const UNQUOTED_VAR_PATTERN = new RegExp(
  `(?<!["'])\\$(?:(?!${PATH_PLACEHOLDERS})CLAUDE_[A-Z_]+|TOOL_INPUT|USER_PROMPT|FILE_PATH|\\{(?!${PATH_PLACEHOLDERS})[A-Z_]+\\})(?!["'])`,
);
const COMMAND_SUBSTITUTION_PATTERN = /\$\([^)]*\$[A-Z]/;
/** A `$` expansion or backtick substitution, other than Claude's path placeholders and plain $HOME. */
const DYNAMIC_EXPANSION = new RegExp(`\`|\\$(?!\\{?(?:${PATH_PLACEHOLDERS}|HOME\\b))[({A-Za-z_@*0-9]`);

/**
 * Shell text that is evaluated a second time with expanded data in it: `eval`
 * or `exec` as a command word with an expansion in its arguments, or a shell
 * `-c` script that the outer shell expands (unquoted or double-quoted). A
 * single-quoted `bash -c '…'` script is constant — its own contents are
 * judged by the other patterns — and `docker compose exec` / `npm exec` are
 * not the shell builtin.
 */
function evaluatesDynamicText(cmd: string): boolean {
  for (const raw of cmd.split(/;|&&|\|\||\||\n/)) {
    // drop sudo / env / VAR=value prefixes to reach the command word
    const seg = raw.trim().replace(/^(?:(?:sudo|env|command|nohup)(?:\s+-\S+)*\s+|[A-Za-z_][A-Za-z0-9_]*=\S*\s+)+/, '');
    const word = /^(\S+)\s*(.*)$/s.exec(seg);
    if (!word) continue;
    const [, head, rest] = word;
    if ((head === 'eval' || head === 'exec') && DYNAMIC_EXPANSION.test(rest)) return true;
    if (/^(?:\S*\/)?(?:ba|z|da|k|mk)?sh$/.test(head)) {
      const c = /(?:^|\s)-[a-zA-Z]*c[a-zA-Z]*\s+(.*)$/s.exec(rest);
      if (c && !c[1].startsWith("'") && DYNAMIC_EXPANSION.test(c[1])) return true;
    }
  }
  return false;
}
// `curl … | bash`, `jq -r .tool_input.command | sh`: whatever arrives on the
// pipe (a download, or the hook's JSON input) runs as a script
const PIPE_TO_SHELL_PATTERN = /\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:\S*\/)?(?:env\s+)?(?:ba|z|da|k|mk|fi)?sh\b(?!\s+[^\s|;&-]\S*)/;

interface HookSpec {
  type?: string;
  command?: string;
  args?: unknown;
}

interface HookEntry {
  matcher?: string;
  hooks?: HookSpec[];
}

/**
 * The shell script a hook runs, or undefined when there is none. Exec form
 * (`args` present) spawns `command` directly with no shell, so `$VAR` and
 * pipes are literal text — unless the executable is itself a shell given
 * `-c <script>`.
 */
function shellScript(hook: HookSpec): string | undefined {
  if (typeof hook.command !== 'string') return undefined;
  if (!Array.isArray(hook.args)) return hook.command;
  const args = hook.args.filter((a): a is string => typeof a === 'string');
  if (!shellCommandWrapper(hook.command, args)) return undefined;
  const at = args.findIndex(a => /^-[a-zA-Z]*c[a-zA-Z]*$/.test(a));
  return at >= 0 ? args[at + 1] : undefined;
}

export const cc003 = defineCheck({
  id: 'CC-003',
  name: 'Unsafe Hook Commands',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Claude Code hooks that exec untrusted shell input without quoting',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const hooks = config.data.hooks as Record<string, unknown> | undefined;
      if (!hooks || typeof hooks !== 'object') continue;

      for (const [event, entries] of Object.entries(hooks)) {
        if (!Array.isArray(entries)) continue;
        for (const entry of entries as HookEntry[]) {
          const hookList = Array.isArray(entry?.hooks) ? entry.hooks : [];
          for (const hook of hookList) {
            if (!hook || typeof hook !== 'object') continue;
            const cmd = shellScript(hook);
            if (typeof cmd !== 'string') continue;

            const reasons: string[] = [];
            if (UNQUOTED_VAR_PATTERN.test(cmd)) {
              reasons.push('uses unquoted $-variables that could expand into a shell injection');
            }
            if (COMMAND_SUBSTITUTION_PATTERN.test(cmd)) {
              reasons.push('embeds variables inside command substitution');
            }
            if (evaluatesDynamicText(cmd)) {
              reasons.push('re-evaluates expanded text (eval/exec or an outer-quoted sh -c script) — data becomes code');
            }
            if (PIPE_TO_SHELL_PATTERN.test(cmd)) {
              reasons.push('pipes data into a shell — downloaded or hook-input text runs as a script');
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

    return h.fromEvidence(evidence, {
      passed: 'No unsafe hook commands detected',
      failed: (n) => `Found ${n} hook command(s) that may execute untrusted input`,
      fixDescription: 'Quote $-variables ("$VAR"), avoid eval/sh -c and piping into a shell, or use exec form (`args`) so no shell runs',
    });
  },
});
