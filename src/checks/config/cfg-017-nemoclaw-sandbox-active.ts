import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { registeredSandboxes } from './nemoclaw-state.js';

export const cfg017 = defineCheck({
  id: 'CFG-017',
  name: 'NemoClaw Sandbox Active',
  category: 'config',
  severity: 'warning',
  description: 'Check if NemoClaw sandbox is actively deployed (not just installed)',
  supportedAgents: ['openclaw', 'nemoclaw'],

  async run(ctx, h) {
    // OpenClaw without NemoClaw: CFG-016 carries the recommendation
    if (!(await ctx.fs.access(join(ctx.fs.homedir(), '.nemoclaw')))) {
      return h.passed('NemoClaw not installed — not applicable (see CFG-016)');
    }
    const stateFile = join(ctx.fs.homedir(), '.nemoclaw', 'state', 'nemoclaw.json');

    if (!(await ctx.fs.access(stateFile))) {
      // Current releases no longer write the state file; the sandbox registry
      // is the persisted record of deployments.
      const registry = await registeredSandboxes(ctx.fs);
      if (registry && registry.sandboxes.length > 0) {
        const names = registry.sandboxes.map(s => s.entry.stopped === true ? `${s.name} (stopped)` : s.name);
        return h.result({
          passed: true,
          message: `NemoClaw sandbox(es) deployed: ${names.join(', ')}`,
          evidence: [{ file: registry.file, detail: `Registered sandboxes: ${names.join(', ')}` }],
        });
      }
      return h.result({
        passed: false,
        message: 'NemoClaw sandbox not deployed — no state file and no registered sandbox',
      });
    }

    try {
      const raw = await ctx.fs.readFile(stateFile);
      const state = JSON.parse(raw) as Record<string, unknown>;

      const lastAction = state.lastAction as string | undefined;
      const sandboxName = state.sandboxName as string | undefined;
      const lastRunId = state.lastRunId as string | undefined;

      if (!lastRunId && !lastAction) {
        return h.result({
          passed: false,
          message: 'NemoClaw is installed but no sandbox has been deployed',
        });
      }

      return h.result({
        passed: true,
        message: `NemoClaw sandbox "${sandboxName ?? 'openclaw'}" is deployed (action: ${lastAction ?? 'unknown'})`,
        evidence: [{
          file: stateFile,
          detail: `runId=${lastRunId ?? 'none'}, action=${lastAction ?? 'none'}, sandbox=${sandboxName ?? 'default'}`,
        }],
      });
    } catch {
      return h.result({
        passed: false,
        message: 'NemoClaw state file exists but could not be parsed',
      });
    }
  },
});
