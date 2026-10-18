/**
 * AI agent CLIs started with their approval prompts or sandbox turned off.
 * A skill that runs `claude --dangerously-skip-permissions -p …` hands its
 * prompt to a second agent that executes any tool without asking — outside
 * the permission rules of the agent that loaded the skill. A "program run
 * directly" is otherwise informational (SKL-003); this is not.
 *
 * Flags as documented by each vendor (verified 2026-10):
 *  - Claude Code: `--dangerously-skip-permissions`, `--permission-mode bypassPermissions`
 *    (`acceptEdits` / `auto` approve part of the work) — code.claude.com/docs/en/cli-reference
 *  - Gemini CLI: `--yolo`/`-y`, `--approval-mode yolo` (`auto_edit`) — google-gemini/gemini-cli docs/cli/cli-reference.md
 *  - Qwen Code: `--yolo`/`-y`, `--approval-mode yolo` (`auto-edit`, `auto`) — qwen-code docs
 *  - Amazon Q / Kiro: `chat --trust-all-tools`/`-a` (`--trust-tools=…`) — aws/amazon-q-developer-cli, kiro.dev
 *  - Codex: `--dangerously-bypass-approvals-and-sandbox`/`--yolo`; `-a never`, `-s danger-full-access`,
 *    `--approve-for-me`, legacy `--full-auto` — openai/codex utils/cli
 *  - Cursor: `--force`/`-f`/`--yolo` (`--sandbox disabled`, `--approve-mcps`) — cursor.com/docs/cli/reference/parameters
 *  - Copilot CLI: `--allow-all-tools`, `--allow-all`/`--yolo` (`--allow-all-paths`, `--allow-all-urls`) — docs.github.com
 *  - OpenCode: `--auto` — opencode.ai/docs/cli
 *  - Devin CLI: `--permission-mode dangerous|yolo|bypass` (`autonomous`) — docs.devin.ai
 *  - Abacus.AI CLI: `--dangerously-skip-permissions`, `--permission-mode yolo` (`accept-edits`) — abacus.ai help
 *  - Aider: `--yes-always` — aider.chat/docs/config/options.html
 */

export interface AgentBypass {
  agent: string;
  flag: string;
  /** critical: every prompt off; warning: part of the work approved, or the sandbox off. */
  level: 'critical' | 'warning';
}

interface FlagRule {
  agents: RegExp;
  /** Subcommand the flag belongs to (`q chat`). */
  sub?: RegExp;
  full: RegExp;
  partial?: RegExp;
}

const RULES: FlagRule[] = [
  { agents: /^claude$/, full: /^--dangerously-skip-permissions$|^--permission-mode[= ]bypassPermissions$/, partial: /^--permission-mode[= ](?:acceptEdits|auto)$/ },
  { agents: /^gemini$/, full: /^(?:--yolo|-y|--approval-mode[= ]yolo)$/, partial: /^--approval-mode[= ]auto_edit$/ },
  { agents: /^qwen$/, full: /^(?:--yolo|-y|--approval-mode[= ]yolo)$/, partial: /^--approval-mode[= ](?:auto-edit|auto)$/ },
  { agents: /^(?:q|kiro-cli)$/, sub: /^chat$/, full: /^(?:--trust-all-tools|-a)$/, partial: /^--trust-tools=\S+$/ },
  { agents: /^codex$/, full: /^(?:--dangerously-bypass-approvals-and-sandbox|--yolo)$/, partial: /^(?:--full-auto|--approve-for-me|--not-so-yolo|--dangerously-bypass-hook-trust|(?:-a|--ask-for-approval)[= ]never|(?:-s|--sandbox)[= ]danger-full-access)$/ },
  { agents: /^cursor-agent$/, full: /^(?:--force|-f|--yolo)$/, partial: /^(?:--sandbox[= ]disabled|--approve-mcps)$/ },
  { agents: /^copilot$/, full: /^(?:--allow-all-tools|--allow-all|--yolo)$/, partial: /^(?:--allow-all-paths|--allow-all-urls)$/ },
  { agents: /^opencode$/, full: /^--auto$/ },
  { agents: /^devin$/, full: /^--permission-mode[= ](?:dangerous|yolo|bypass)$/, partial: /^--permission-mode[= ]autonomous$/ },
  { agents: /^abacus(?:ai)?$/, full: /^(?:--dangerously-skip-permissions|--permission-mode[= ]yolo)$/, partial: /^(?:--auto-accept-edits|--permission-mode[= ]accept-edits)$/ },
  { agents: /^aider$/, full: /^--yes-always$/ },
];

/** Leading words that run the next one: `npx -y`, `sudo`, `env A=b`, `sh -c '…'`. */
const WRAPPER = /^(?:sudo|env|exec|nohup|time|npx|bunx|pnpx|sh|bash|zsh|dash)$/;
/** npm packages that install an agent CLI, by package name (scope dropped). */
const PACKAGE_BINARY: Record<string, string> = {
  'claude-code': 'claude', 'gemini-cli': 'gemini', 'qwen-code': 'qwen', 'opencode-ai': 'opencode',
};

function programName(word: string): string {
  const base = word.replace(/^['"]+|['"]+$/g, '').replace(/^.*\//, '').replace(/@[\w.-]+$/, '');
  return PACKAGE_BINARY[base] ?? base;
}

/**
 * The bypass an agent command line asks for, if any. `command` is the static
 * text of the call (program and argv joined by spaces, `${…}` for computed
 * parts), as the analyzers record it.
 */
export function agentBypass(command: string | undefined): AgentBypass | undefined {
  if (!command) return undefined;
  const words = command.trim().split(/\s+/);
  let i = 0;
  while (i < words.length && (WRAPPER.test(programName(words[i])) || /^-/.test(words[i]) || /^\w+=/.test(words[i]))) i++;
  const program = programName(words[i] ?? '');
  const rule = RULES.find(r => r.agents.test(program));
  if (!rule) return undefined;
  const args = words.slice(i + 1).map(a => a.replace(/^['"]+|['"]+$/g, ''));
  if (rule.sub && !args.some(a => rule.sub!.test(a))) return undefined;
  // `--permission-mode bypassPermissions` as two words is the same flag
  const flags = args.flatMap((a, k) => (/^-/.test(a) && args[k + 1] && !/^-/.test(args[k + 1]) ? [a, `${a} ${args[k + 1]}`] : [a]));
  const full = flags.find(f => rule.full.test(f));
  if (full) return { agent: program, flag: full, level: 'critical' };
  const partial = rule.partial && flags.filter(f => rule.partial!.test(f));
  // Codex with both approvals off and full disk access is the full bypass
  if (program === 'codex' && partial && partial.some(f => /never$/.test(f)) && partial.some(f => /danger-full-access$/.test(f))) {
    return { agent: program, flag: partial.join(' + '), level: 'critical' };
  }
  return partial && partial.length > 0 ? { agent: program, flag: partial[0], level: 'warning' } : undefined;
}
