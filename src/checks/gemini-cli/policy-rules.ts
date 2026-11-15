import type { Evidence, ParsedConfig } from '../../core/types.js';
import { commandStem, INTERPRETER_COMMANDS, SHELL_COMMANDS, WRAPPER_COMMANDS } from '../../analyzers/command-families.js';

/**
 * Gemini CLI policy engine rules (`[[rule]]` in policies/*.toml,
 * geminicli.com/docs/reference/policy-engine). An `allow` decision runs the
 * matching tool call without asking. Judged here: rules that allow every
 * tool (`toolName = "*"`), every shell command (`run_shell_command` with no
 * commandPrefix / commandRegex / argsPattern, or a catch-all regex), a shell,
 * interpreter, wrapper or network/deletion command as a prefix (it runs
 * anything it is given), or every tool of an MCP server (`mcpName` with no or
 * a wildcard `toolName`, `mcp_*`, `mcp_<server>_*`). A rule limited to
 * `modes = ["yolo"]` adds nothing — yolo already allows everything.
 */

const RISKY_COMMANDS = new Set(['rm', 'sudo', 'curl', 'wget', 'nc', 'ncat', 'netcat', 'telnet', 'ssh', 'scp']);
const SHELL_TOOL = 'run_shell_command';
/** A regex that matches any command (`.*`, `.+`, `^.*$`, `[\s\S]*`). */
const CATCH_ALL_REGEX = /^\^?(?:\.\*|\.\+|\[\\s\\S\][*+]|\(\.\*\))\$?$/;

function list(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
}

/** Why an allowed command prefix runs far more than one command, or undefined. */
function broadPrefix(prefix: string): string | undefined {
  const first = prefix.trim().split(/\s+/)[0] ?? '';
  if (first === '' || first === '*') return 'matches every shell command';
  const stem = commandStem(first.split('/').pop() ?? first);
  if (SHELL_COMMANDS.has(stem) || WRAPPER_COMMANDS.has(stem)) return `allows ${first}, which runs any command it is given`;
  if (INTERPRETER_COMMANDS.has(stem)) return `allows the ${first} interpreter, which runs any code it is given`;
  if (RISKY_COMMANDS.has(stem)) return `allows any ${first} command (network transfer, deletion or privilege escalation)`;
  return undefined;
}

/** `mcp_<x>_*`: the tool name is `mcp_<server>_<tool>` and a server name
 *  may hold `_`, so `mcp_github_get_*` is every tool of server "github_get"
 *  or the `get_*` tools of server "github". */
function mcpPrefixDetail(x: string): string {
  const cut = x.indexOf('_');
  const alt = cut > 0 ? ` (or the "${x.slice(cut + 1)}_*" tools of server "${x.slice(0, cut)}")` : '';
  return `Every tool of MCP server "${x}"${alt} runs without confirmation`;
}

/** Whether `config` is a policy file (a `.toml` holding `[[rule]]` tables). */
export function isPolicyFile(config: ParsedConfig): boolean {
  return config.filePath.endsWith('.toml') && Array.isArray(config.data.rule);
}

export function policyEvidence(config: ParsedConfig): Evidence[] {
  const out: Evidence[] = [];
  const rules = Array.isArray(config.data.rule) ? config.data.rule : [];
  rules.forEach((raw, i) => {
    if (!raw || typeof raw !== 'object') return;
    const rule = raw as Record<string, unknown>;
    if (typeof rule.decision !== 'string' || rule.decision.toLowerCase() !== 'allow') return;
    const modes = list(rule.modes);
    if (modes.length > 0 && modes.every(m => m.toLowerCase() === 'yolo')) return;
    const at = `rule[${i}]`;
    const push = (what: string, detail: string) => out.push({ file: config.filePath, snippet: `${at}: ${what} → allow`, detail });

    const tools = list(rule.toolName);
    const prefixes = list(rule.commandPrefix);
    const regex = typeof rule.commandRegex === 'string' ? rule.commandRegex : undefined;
    const argsPattern = typeof rule.argsPattern === 'string' ? rule.argsPattern : undefined;
    const mcpName = typeof rule.mcpName === 'string' ? rule.mcpName : undefined;

    if (mcpName !== undefined) {
      if (tools.length === 0 || tools.includes('*')) {
        if (argsPattern) return;
        push(`mcpName = "${mcpName}"${tools.length ? ', toolName = "*"' : ''}`, mcpName === '*'
          ? 'Every tool of every MCP server runs without confirmation — a prompt-injected call reaches all of them unchecked'
          : `Every tool of MCP server "${mcpName}" runs without confirmation — like trust: true for that server`);
      }
      return;
    }

    // commandPrefix / commandRegex are sugar for toolName = "run_shell_command"
    const effective = tools.length > 0 ? tools : prefixes.length > 0 || regex !== undefined ? [SHELL_TOOL] : [];
    for (const tool of effective) {
      if (tool === '*') {
        if (argsPattern) continue;
        push('toolName = "*"', 'Every tool — shell commands, file writes, web fetches, MCP tools — runs without confirmation (yolo for every session)');
      } else if (tool === 'mcp_*' || /^mcp_[^*]+_\*$/.test(tool)) {
        if (argsPattern) continue;
        push(`toolName = "${tool}"`, tool === 'mcp_*'
          ? 'Every tool of every MCP server runs without confirmation'
          : mcpPrefixDetail(tool.slice(4, -2)));
      } else if (tool === SHELL_TOOL) {
        if (prefixes.length === 0 && regex === undefined && argsPattern === undefined) {
          push(`toolName = "${SHELL_TOOL}"`, 'Every shell command runs without confirmation — the rule has no commandPrefix / commandRegex / argsPattern');
          continue;
        }
        if (regex !== undefined && CATCH_ALL_REGEX.test(regex.trim())) {
          push(`commandRegex = "${regex}"`, 'The command regex matches every shell command — all of them run without confirmation');
          continue;
        }
        for (const p of prefixes) {
          const reason = broadPrefix(p);
          if (reason) push(`commandPrefix = "${p}"`, `Shell commands run without confirmation: the prefix ${reason}`);
        }
      }
    }
  });
  return out;
}
