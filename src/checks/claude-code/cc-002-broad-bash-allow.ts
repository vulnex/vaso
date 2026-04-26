import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';

const DANGEROUS_BASH_PATTERNS = [
  { pattern: /^Bash$/, reason: 'bare "Bash" allows any shell command' },
  { pattern: /^Bash\(\*\)$/, reason: 'Bash(*) allows any shell command' },
  { pattern: /^Bash\(rm:/, reason: 'rm with broad arguments can destroy files' },
  { pattern: /^Bash\(sudo:/, reason: 'sudo grants privileged execution' },
  { pattern: /^Bash\(curl:/, reason: 'curl can fetch and execute remote payloads' },
  { pattern: /^Bash\(wget:/, reason: 'wget can fetch arbitrary remote content' },
  { pattern: /^Bash\(eval:/, reason: 'eval executes arbitrary strings as commands' },
  { pattern: /^Bash\(sh:/, reason: 'sh can run any command in a sub-shell' },
  { pattern: /^Bash\(bash:/, reason: 'bash can run any command in a sub-shell' },
  { pattern: /^Bash\(chmod:/, reason: 'chmod can change file permissions across the system' },
  { pattern: /^Bash\(.*\*\)$/, reason: 'wildcard arguments expand the attack surface' },
];

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
        for (const { pattern, reason } of DANGEROUS_BASH_PATTERNS) {
          if (pattern.test(entry)) {
            evidence.push({
              file: config.filePath,
              snippet: entry,
              detail: reason,
            });
            break;
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No overly broad Bash permissions detected',
      failed: (n) => `Found ${n} risky Bash allow pattern(s) — narrow them to specific commands`,
      fixDescription: 'Replace broad Bash patterns with specific subcommands (e.g. Bash(git:status))',
    });
  },
});
