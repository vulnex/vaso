import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUntrustedWorkspace } from '../../adapters/folder-trust.js';
import { qwenWorkspaceTrusted } from '../../adapters/qwen-code.js';

// Tools whose blanket auto-approval runs commands or changes files. Aliases
// from Qwen settings.md ("Tool name aliases"); Read/Grep/Glob are read-only.
const RISKY_TOOLS = new Set([
  'bash', 'shell', 'run_shell_command',
  'edit', 'editfile', 'write', 'writefile', 'write_file', 'notebookedit', 'notebook_edit',
  'webfetch', 'web_fetch',
]);
const RULE = /^\s*([A-Za-z_][\w-]*)\s*(?:\((.*)\))?\s*$/s;

/**
 * The tool family a rule name covers (settings.md "Tool name aliases" and
 * meta-categories: `Edit` covers edit, write_file and notebook_edit). A deny
 * or ask rule is a net only for its own family — `Read(.env)` does nothing
 * for `Bash(*)`.
 */
const FAMILIES: Record<string, string> = {
  bash: 'shell', shell: 'shell', run_shell_command: 'shell',
  edit: 'edit', editfile: 'edit', write: 'edit', writefile: 'edit', write_file: 'edit',
  notebookedit: 'edit', notebookedittool: 'edit', notebook_edit: 'edit',
  webfetch: 'fetch', web_fetch: 'fetch',
};

function family(rule: string): string | undefined {
  if (rule.trim() === '*') return '*';
  const m = RULE.exec(rule);
  return m ? FAMILIES[m[1].toLowerCase()] : undefined;
}
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
  description: 'Detect permissions.allow (or legacy tools.allowed) auto-approving every shell/edit/fetch call when no deny or ask rule covers that tool',
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
      // `ask` outranks `allow` (deny > ask > allow), so it is a net too
      const nets = [
        ...strings(perms && typeof perms === 'object' ? perms.deny : undefined),
        ...strings(perms && typeof perms === 'object' ? perms.ask : undefined),
        ...strings(tools && typeof tools === 'object' ? tools.exclude : undefined),
      ];
      const covered = new Set(nets.map(family).filter((f): f is string => !!f));

      // A broad allow is netted by a deny/ask rule on the same tool family;
      // `*` (every tool) needs a net on shell commands at least
      const broad = allow.filter(isBroadRule).filter(rule => {
        const f = family(rule);
        if (covered.has('*')) return false;
        return f === '*' ? !covered.has('shell') : !(f && covered.has(f));
      });
      if (broad.length === 0) continue;

      evidence.push({
        file: config.filePath,
        snippet: `permissions.allow has ${broad.length} broad rule(s) with no deny/ask rule for the same tool`,
        detail: `Broad allow rules without a deny net for their tool: ${broad.slice(0, 3).join(', ')}${broad.length > 3 ? ', …' : ''}`,
      });
    }

    await markUntrustedWorkspace(ctx, evidence, qwenWorkspaceTrusted);

    return h.fromEvidence(evidence, {
      passed: 'Qwen permissions either lack broad allow rules or have a deny net',
      failed: () => 'Qwen permissions.allow includes broad patterns with no deny/ask rule for the same tool',
      fixDescription: 'Add explicit deny rules (e.g., "Bash(rm -rf *)", "Read(.env)") or narrow the allow patterns (e.g., "Bash(git *)")',
    });
  },
});
