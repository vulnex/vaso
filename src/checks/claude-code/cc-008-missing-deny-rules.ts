import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

const RECOMMENDED_DENY_PATTERNS = [
  'Bash(rm:*)',
  'Bash(sudo:*)',
  'Bash(curl:*)',
];

export const cc008: CheckModule = {
  id: 'CC-008',
  name: 'Missing Sensitive Deny Rules',
  category: 'coding-agent',
  severity: 'info',
  description: 'Suggest adding common deny rules when an allow list is configured but no deny list is set',
  supportedAgents: ['claude-code'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const allow = getNestedValue(config.data, 'permissions.allow') as unknown;
      const deny = getNestedValue(config.data, 'permissions.deny') as unknown;

      // Only flag when an allow list is configured (i.e. user is actively managing perms)
      if (!Array.isArray(allow) || allow.length === 0) continue;

      const denyList = Array.isArray(deny) ? deny.filter((d): d is string => typeof d === 'string') : [];
      const missing = RECOMMENDED_DENY_PATTERNS.filter(p => !denyList.includes(p));

      if (missing.length === RECOMMENDED_DENY_PATTERNS.length) {
        evidence.push({
          file: config.filePath,
          detail: `permissions.allow is configured but no deny rules cover dangerous commands (${missing.join(', ')})`,
        });
      }
    }

    return {
      id: 'CC-008',
      name: 'Missing Sensitive Deny Rules',
      category: 'coding-agent',
      severity: 'info',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Permission deny list covers common destructive commands or none configured'
        : 'No deny rules cover destructive commands — consider adding rm/sudo/curl deny patterns',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Add Bash(rm:*), Bash(sudo:*), Bash(curl:*) to permissions.deny',
    };
  },
};
