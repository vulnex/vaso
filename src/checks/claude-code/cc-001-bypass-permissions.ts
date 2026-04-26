import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

const DANGEROUS_MODES = new Set(['bypassPermissions', 'acceptAll', 'dangerouslySkipPermissions']);

export const cc001: CheckModule = {
  id: 'CC-001',
  name: 'Permission Bypass Mode',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when Claude Code is configured to bypass tool approval prompts',
  supportedAgents: ['claude-code'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const mode = getNestedValue(config.data, 'permissions.defaultMode') as string | undefined;
      if (mode && DANGEROUS_MODES.has(mode)) {
        evidence.push({
          file: config.filePath,
          detail: `permissions.defaultMode = "${mode}" — all tool executions skip user confirmation`,
        });
      }

      const skipFlag = config.data.dangerouslySkipPermissions;
      if (skipFlag === true) {
        evidence.push({
          file: config.filePath,
          detail: 'dangerouslySkipPermissions = true — agent will execute tools without approval',
        });
      }
    }

    return {
      id: 'CC-001',
      name: 'Permission Bypass Mode',
      category: 'coding-agent',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Permission approval prompts are not bypassed'
        : 'Permission bypass mode is enabled — Claude Code will execute tools without confirmation',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Remove permissions.defaultMode = "bypassPermissions" or set it to "default"/"acceptEdits"',
    };
  },
};
