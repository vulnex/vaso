import { join } from 'node:path';
import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';

export const cfg017: CheckModule = {
  id: 'CFG-017',
  name: 'NemoClaw Sandbox Active',
  category: 'config',
  severity: 'warning',
  description: 'Check if NemoClaw sandbox is actively deployed (not just installed)',
  supportedAgents: ['openclaw', 'nemoclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const stateFile = join(ctx.fs.homedir(), '.nemoclaw', 'state', 'nemoclaw.json');

    if (!(await ctx.fs.access(stateFile))) {
      return {
        id: 'CFG-017',
        name: 'NemoClaw Sandbox Active',
        category: 'config',
        severity: 'warning',
        passed: false,
        message: 'NemoClaw state file not found — sandbox not deployed',
      };
    }

    try {
      const raw = await ctx.fs.readFile(stateFile);
      const state = JSON.parse(raw) as Record<string, unknown>;

      const lastAction = state.lastAction as string | undefined;
      const sandboxName = state.sandboxName as string | undefined;
      const lastRunId = state.lastRunId as string | undefined;

      if (!lastRunId && !lastAction) {
        return {
          id: 'CFG-017',
          name: 'NemoClaw Sandbox Active',
          category: 'config',
          severity: 'warning',
          passed: false,
          message: 'NemoClaw is installed but no sandbox has been deployed',
        };
      }

      return {
        id: 'CFG-017',
        name: 'NemoClaw Sandbox Active',
        category: 'config',
        severity: 'warning',
        passed: true,
        message: `NemoClaw sandbox "${sandboxName ?? 'openclaw'}" is deployed (action: ${lastAction ?? 'unknown'})`,
        evidence: [{
          file: stateFile,
          detail: `runId=${lastRunId ?? 'none'}, action=${lastAction ?? 'none'}, sandbox=${sandboxName ?? 'default'}`,
        }],
      };
    } catch {
      return {
        id: 'CFG-017',
        name: 'NemoClaw Sandbox Active',
        category: 'config',
        severity: 'warning',
        passed: false,
        message: 'NemoClaw state file exists but could not be parsed',
      };
    }
  },
};
