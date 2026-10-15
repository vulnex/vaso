import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

// Tools whose blanket auto-approval runs commands or changes files. Aliases
// from Qwen settings.md ("Tool name aliases"); Read/Grep/Glob are read-only.
const RISKY_TOOLS = new Set([
  'bash', 'shell', 'run_shell_command',
  'edit', 'editfile', 'write', 'writefile', 'write_file', 'notebookedit', 'notebook_edit',
  'webfetch', 'web_fetch',
]);
const RULE = /^\s*([A-Za-z_][\w-]*)\s*(?:\((.*)\))?\s*$/s;
// A specifier made only of wildcards matches every call (`Bash(*)`, `Bash(* *)`, `Edit(**)`)
const ALL_WILDCARD = /^[\s*/]*$/;

/**
 * A rule that auto-approves every call of a risky tool: `*`, a bare tool name
 * (settings.md: `"Bash"` = "All shell commands") or a wildcard-only
 * specifier. Narrow rules such as `Bash(git *)` or `Shell(git status)` are the
 * documented way to scope an allow and are not flagged.
 */
function isBroadRule(rule: string): boolean {
  if (rule.trim() === '*') return true;
  const m = RULE.exec(rule);
  if (!m) return false;
  if (!RISKY_TOOLS.has(m[1].toLowerCase())) return false;
  return m[2] === undefined || ALL_WILDCARD.test(m[2]);
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((a): a is string => typeof a === 'string') : [];
}

export const qc005 = defineCheck({
  id: 'QC-005',
  name: 'Qwen Allow With Empty Deny',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect permissions.allow (or legacy tools.allowed) auto-approving every shell/edit/fetch call when no deny rule exists',
  supportedAgents: ['qwen-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const perms = config.data.permissions as Record<string, unknown> | undefined;
      const tools = config.data.tools as Record<string, unknown> | undefined;
      // tools.allowed / tools.exclude are deprecated but "still honoured at
      // startup" (settings.md migration table)
      const allow = [
        ...strings(perms && typeof perms === 'object' ? perms.allow : undefined),
        ...strings(tools && typeof tools === 'object' ? tools.allowed : undefined),
      ];
      const deny = [
        ...strings(perms && typeof perms === 'object' ? perms.deny : undefined),
        ...strings(tools && typeof tools === 'object' ? tools.exclude : undefined),
      ];

      if (deny.length > 0) continue;
      const broad = allow.filter(isBroadRule);
      if (broad.length === 0) continue;

      evidence.push({
        file: config.filePath,
        snippet: `permissions.allow has ${broad.length} broad rule(s); permissions.deny is empty`,
        detail: `Broad allow rules without a deny net: ${broad.slice(0, 3).join(', ')}${broad.length > 3 ? ', …' : ''}`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'Qwen permissions either lack broad allow rules or have a deny net',
      failed: () => 'Qwen permissions.allow includes broad patterns with empty permissions.deny',
      fixDescription: 'Add explicit deny rules (e.g., "Bash(rm -rf *)", "Read(.env)") or narrow the allow patterns (e.g., "Bash(git *)")',
    });
  },
});
