import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

const MIN_DENYLIST_LENGTH = 5;

export const nb004: CheckModule = {
  id: 'NB-004',
  name: 'Weak ExecTool Denylist',
  category: 'nanobot',
  severity: 'critical',
  description: 'Check if the ExecTool command denylist is missing, empty, or too short to be effective',
  supportedAgents: ['nanobot'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];
    for (const config of ctx.configs) {
      const execTool = getNestedValue(config.data, 'tools.exec')
        ?? getNestedValue(config.data, 'execTool');

      if (!execTool || typeof execTool !== 'object') continue;

      const toolConfig = execTool as Record<string, unknown>;
      const denylist = toolConfig.denyList ?? toolConfig.denylist ?? toolConfig.blockedCommands ?? toolConfig.deny;

      if (!denylist) {
        evidence.push({
          file: config.filePath,
          detail: 'ExecTool has no command denylist — all commands are allowed',
        });
      } else if (Array.isArray(denylist) && denylist.length === 0) {
        evidence.push({
          file: config.filePath,
          detail: 'ExecTool denylist is empty — all commands are allowed',
        });
      } else if (Array.isArray(denylist) && denylist.length < MIN_DENYLIST_LENGTH) {
        evidence.push({
          file: config.filePath,
          detail: `ExecTool denylist has only ${denylist.length} entries (minimum ${MIN_DENYLIST_LENGTH}) — easily bypassed with path tricks like /usr/bin/rm vs rm`,
        });
      }
    }
    return {
      id: 'NB-004', name: 'Weak ExecTool Denylist', category: 'nanobot',
      severity: 'critical', passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'ExecTool denylist is adequately configured'
        : 'ExecTool has a missing or weak command denylist',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true, fixDescription: 'Add a comprehensive command denylist to ExecTool config (rm, curl, wget, chmod, chown, etc.)',
    };
  },
};
