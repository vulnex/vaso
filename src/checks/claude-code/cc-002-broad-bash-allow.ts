import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { DANGEROUS_COMMANDS } from '../devin/dev-001-broad-permissions.js';

/** Why allowing a command family without a prompt is risky. */
const FAMILY_REASONS: Record<string, string> = {
  rm: 'rm with broad arguments can destroy files',
  sudo: 'sudo grants privileged execution',
  su: 'su grants privileged execution',
  doas: 'doas grants privileged execution',
  curl: 'curl can fetch and execute remote payloads or send data out',
  wget: 'wget can fetch arbitrary remote content',
  eval: 'eval executes arbitrary strings as commands',
  chmod: 'chmod can change file permissions across the system',
};

/**
 * The command a Bash rule allows: `Bash(npm run test *)`, `Bash(rm:*)`
 * (the `:*` suffix is the same trailing wildcard), `Bash(python3 -c *)`.
 * Prefix rules are matched per subcommand of a compound command
 * (code.claude.com/docs/en/permissions), so a trailing wildcard on a harmless
 * command is the documented way to allow it — the command is what matters.
 */
function bashRule(entry: string): { family: string; anything: boolean } | undefined {
  if (entry === 'Bash') return { family: '', anything: true };
  const m = /^Bash\((.*)\)$/s.exec(entry);
  if (!m) return undefined;
  const body = m[1].trim().replace(/:\*$/, ' *');
  if (body === '' || body.startsWith('*')) return { family: '', anything: true };
  const first = (body.split(/\s+/)[0] ?? '').split('/').pop() ?? '';
  return { family: first.replace(/^(python|ruby|perl|php|node)\d+(?:\.\d+)*$/, '$1'), anything: false };
}

export const cc002 = defineCheck({
  id: 'CC-002',
  name: 'Broad Bash Allowlist',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect overly broad Bash patterns in Claude Code permissions.allow',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const allow = getNestedValue(config.data, 'permissions.allow') as unknown;
      if (!Array.isArray(allow)) continue;

      for (const entry of allow) {
        if (typeof entry !== 'string') continue;
        const rule = bashRule(entry.trim());
        if (!rule) continue;
        if (rule.anything) {
          evidence.push({ file: config.filePath, snippet: entry, detail: `${entry} allows any shell command` });
        } else if (DANGEROUS_COMMANDS.has(rule.family) || FAMILY_REASONS[rule.family]) {
          evidence.push({
            file: config.filePath,
            snippet: entry,
            detail: FAMILY_REASONS[rule.family]
              ?? `"${rule.family}" runs arbitrary code, opens a shell or reaches the network — allowing it skips the prompt for all of that`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No overly broad Bash permissions detected',
      failed: (n) => `Found ${n} risky Bash allow pattern(s) — narrow them to specific commands`,
      fixDescription: 'Allow specific commands instead (e.g. "Bash(npm run test *)", "Bash(git status)"), and leave shells, interpreters, network and privilege tools to the prompt',
    });
  },
});
