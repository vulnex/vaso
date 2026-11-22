import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { truncateSnippet } from '../../core/patterns.js';
import { shellCommandWrapper } from '../../mcp/shell-wrapper.js';
import { hookCommandRisks, hookExpansion, httpHookRisks, topTier, hookSnippet } from '../../analyzers/hook-commands.js';
import { customCommandRuns } from './custom-commands.js';
import { readSubagents } from './subagents.js';
import { claudeManagedLocks } from './managed-locks.js';

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
const DYNAMIC_EXPANSION = hookExpansion(['CLAUDE_PROJECT_DIR', 'CLAUDE_PLUGIN_ROOT', 'CLAUDE_PLUGIN_DATA', 'CLAUDE_ENV_FILE']);

interface HookSpec {
  type?: string;
  command?: string;
  args?: unknown;
  url?: string;
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

/** Unsafe commands and HTTP targets in one `hooks` object (settings file or frontmatter). */
function hookObjectEvidence(hooksRaw: unknown, file: string, label = 'Hook'): { evidence: Evidence[]; critical: boolean } {
  const evidence: Evidence[] = [];
  let critical = false;
  if (!hooksRaw || typeof hooksRaw !== 'object' || Array.isArray(hooksRaw)) return { evidence, critical };
  const hooks = hooksRaw as Record<string, unknown>;

  for (const [event, entries] of Object.entries(hooks)) {
    if (!Array.isArray(entries)) continue;
    for (const entry of entries as HookEntry[]) {
      const hookList = Array.isArray(entry?.hooks) ? entry.hooks : [];
      for (const hook of hookList) {
        if (!hook || typeof hook !== 'object') continue;
        // HTTP hooks POST the event JSON (prompts, tool input) to `url`
        if (hook.type === 'http' && typeof hook.url === 'string') {
          const risks = httpHookRisks(hook.url);
          const tier = topTier(risks);
          if (!tier) continue;
          evidence.push({
            file,
            snippet: hookSnippet(event, `http ${truncateSnippet(hook.url, 120)}`, entry.matcher ? `(${entry.matcher})` : ''),
            detail: `${label === 'Hook' ? 'HTTP hook' : `${label} (http)`} ${risks.map(r => r.reason).join('; ')}`,
            ...(tier === 'info' ? { mitigated: true } : {}),
          });
          continue;
        }
        const cmd = shellScript(hook);
        if (typeof cmd !== 'string') continue;

        // The download/exfiltration/eval tiers are shared with CUR-015
        // and WS-009 (same model: a shell runs `command` with the event
        // JSON on stdin), so one command gets one tier on every agent;
        // the quoting reasons below are Claude Code's own (warning).
        const risks = hookCommandRisks(cmd, { expansion: DYNAMIC_EXPANSION });
        const reasons = risks.map(r => r.reason);
        let tier = topTier(risks);
        if (UNQUOTED_VAR_PATTERN.test(cmd)) {
          reasons.push('uses unquoted $-variables that could expand into a shell injection');
          if (tier !== 'critical') tier = 'warning';
        }
        if (COMMAND_SUBSTITUTION_PATTERN.test(cmd)) {
          reasons.push('embeds variables inside command substitution');
          if (tier !== 'critical') tier = 'warning';
        }
        if (!tier) continue;
        if (tier === 'critical') critical = true;
        evidence.push({
          file,
          snippet: hookSnippet(event, cmd.slice(0, 120), entry.matcher ? `(${entry.matcher})` : ''),
          detail: `${label} command ${reasons.join('; ')}`,
          ...(tier === 'info' ? { mitigated: true } : {}),
        });
      }
    }
  }
  return { evidence, critical };
}

export const cc003 = defineCheck({
  id: 'CC-003',
  name: 'Unsafe Hook Commands',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Claude Code hooks and custom slash commands (`!`cmd`` lines) that download and execute code, send credentials or hook input over the network (incl. http hooks), re-evaluate input as code, or exec untrusted shell input without quoting',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let critical = false;

    // Managed locks: allowManagedHooksOnly blocks user, project and local
    // hooks; a managed disableAllHooks stops every hook; disableAllHooks in
    // a user/project/local file stops the hooks of those scopes only
    const locks = await claudeManagedLocks(ctx);
    const scopedOff = ctx.configs.find(c => !locks.managedFiles.has(c.filePath) && (c.data as Record<string, unknown> | undefined)?.disableAllHooks === true);
    const offReason = (file: string): string | undefined => {
      if (locks.allHooksOff) return `${locks.allHooksOff} sets disableAllHooks`;
      if (locks.managedFiles.has(file)) return undefined;
      if (locks.hooksOnly) return `${locks.hooksOnly} sets allowManagedHooksOnly`;
      return scopedOff ? `${scopedOff.filePath} sets disableAllHooks` : undefined;
    };
    for (const config of ctx.configs) {
      const found = hookObjectEvidence(config.data.hooks, config.filePath);
      const off = offReason(config.filePath);
      if (off) {
        for (const e of found.evidence) {
          e.mitigated = true;
          e.detail = `${e.detail} (mitigated: not run — ${off})`;
        }
      } else if (found.critical) {
        critical = true;
      }
      evidence.push(...found.evidence);
    }

    // Sub-agent frontmatter `hooks` (same format as settings hooks): they
    // run while that sub-agent runs (code.claude.com/docs/en/hooks)
    for (const agent of await readSubagents(ctx)) {
      const found = hookObjectEvidence(agent.frontmatter.hooks, agent.file, 'Sub-agent hook');
      if (locks.allHooksOff) {
        for (const e of found.evidence) {
          e.mitigated = true;
          e.detail = `${e.detail} (mitigated: not run — ${locks.allHooksOff} sets disableAllHooks)`;
        }
      } else if (found.critical) {
        critical = true;
      }
      evidence.push(...found.evidence);
    }

    // Custom slash commands: their `!`cmd`` lines and ```! blocks run in a
    // shell whenever the command is invoked — the same as a hook
    const shellOff = ctx.configs.some(c => (c.data as Record<string, unknown> | undefined)?.disableSkillShellExecution === true);
    for (const run of await customCommandRuns(ctx)) {
      const risks = hookCommandRisks(run.command, { expansion: DYNAMIC_EXPANSION });
      const tier = topTier(risks);
      if (!tier) continue;
      const live = tier !== 'info' && !shellOff;
      if (live && tier === 'critical') critical = true;
      const reasons = risks.map(r => r.reason.replace('every time the hook fires', 'every time the command runs').replace(/hook input/g, 'command input'));
      evidence.push({
        file: run.file,
        line: run.line,
        snippet: `command: ${truncateSnippet(run.command.replace(/\s*\n\s*/g, ' ; '), 120)}`,
        detail: `Custom command's ${run.form} shell command (Claude Code runs it when the command is invoked) ${reasons.join('; ')}${shellOff ? ' — not run: disableSkillShellExecution is set' : ''}`,
        ...(live ? {} : { mitigated: true }),
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'No unsafe hook commands detected',
      failed: (n) => `Found ${n} hook or custom-command shell command(s) that download code, send data out or may execute untrusted input`,
      severity: critical ? 'critical' : 'warning',
      fixDescription: 'Remove hooks and custom commands you did not add yourself (a project .claude/settings.json or .claude/commands/ arrives with the repo); run vendored, reviewed scripts instead of downloads, send audit data only to endpoints you control over https, quote $-variables ("$VAR"), and avoid eval/sh -c and piping into a shell — or use exec form (`args`) so no shell runs',
    });
  },
});
