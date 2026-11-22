import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { getNestedValue } from '../../core/utils.js';
import { claudeManagedLocks } from './managed-locks.js';

const RECOMMENDED_DENY_PATTERNS = [
  'Bash(rm:*)',
  'Bash(sudo:*)',
  'Bash(curl:*)',
];

/** Whether a deny rule covers `Bash(<cmd>:*)` — written as `Bash(cmd:*)`,
 *  `Bash(cmd *)`, `Bash(cmd)`, or a rule denying all of Bash. */
function denies(rule: string, pattern: string): boolean {
  const cmd = /^Bash\((\w+):\*\)$/.exec(pattern)?.[1];
  if (!cmd) return rule === pattern;
  const r = rule.replace(/\s+/g, ' ').trim();
  if (r === 'Bash' || r === 'Bash(*)') return true;
  return new RegExp(`^Bash\\( ?${cmd}(?::\\*| \\*|) ?\\)$`).test(r);
}

export const cc008 = defineCheck({
  id: 'CC-008',
  name: 'Missing Sensitive Deny Rules',
  category: 'coding-agent',
  severity: 'info',
  description: 'Suggest adding common deny rules when an allow list is configured but no deny list is set',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const locks = await claudeManagedLocks(ctx);
    // Deny rules merge across every settings scope (lists merge, deny wins),
    // so a deny list in one file covers the allow list in another
    const applies = (file: string) => !locks.permissionRulesOnly || locks.managedFiles.has(file);
    const mergedDeny = ctx.configs.filter(c => applies(c.filePath)).flatMap(c => {
      const d = getNestedValue(c.data, 'permissions.deny') as unknown;
      return Array.isArray(d) ? d.filter((x): x is string => typeof x === 'string') : [];
    });

    for (const config of ctx.configs) {
      // allowManagedPermissionRulesOnly: this file's allow list doesn't apply
      if (locks.permissionRulesOnly && !locks.managedFiles.has(config.filePath)) continue;
      const allow = getNestedValue(config.data, 'permissions.allow') as unknown;

      // Only flag when an allow list is configured (i.e. user is actively managing perms)
      if (!Array.isArray(allow) || allow.length === 0) continue;

      const denyList = mergedDeny;
      const missing = RECOMMENDED_DENY_PATTERNS.filter(p => !denyList.some(rule => denies(rule, p)));

      if (missing.length === RECOMMENDED_DENY_PATTERNS.length) {
        evidence.push({
          file: config.filePath,
          detail: `permissions.allow is configured but no deny rules cover dangerous commands (${missing.join(', ')})`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Permission deny list covers common destructive commands or none configured',
      failed: () => 'No deny rules cover destructive commands — consider adding rm/sudo/curl deny patterns',
      fixDescription: 'Add Bash(rm:*), Bash(sudo:*), Bash(curl:*) to permissions.deny',
    });
  },
});
