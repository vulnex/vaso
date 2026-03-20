import { join } from 'node:path';
import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

export const cfg016: CheckModule = {
  id: 'CFG-016',
  name: 'NemoClaw Hardening',
  category: 'config',
  severity: 'info',
  description: 'Check if NemoClaw sandbox hardening is installed for OpenClaw',
  supportedAgents: ['openclaw', 'nemoclaw'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const nemoDir = join(ctx.fs.homedir(), '.nemoclaw');
    const stateFile = join(nemoDir, 'state', 'nemoclaw.json');
    const configFile = join(nemoDir, 'config.json');

    const dirExists = await ctx.fs.access(nemoDir);
    if (!dirExists) {
      return {
        id: 'CFG-016',
        name: 'NemoClaw Hardening',
        category: 'config',
        severity: 'info',
        passed: false,
        message: 'NemoClaw sandbox hardening is not installed — consider deploying NemoClaw for Landlock + seccomp + network isolation',
      };
    }

    const evidence: Evidence[] = [];
    evidence.push({ file: nemoDir, detail: 'NemoClaw directory detected' });

    if (await ctx.fs.access(stateFile)) {
      try {
        const raw = await ctx.fs.readFile(stateFile);
        const state = JSON.parse(raw) as Record<string, unknown>;
        const action = state.lastAction as string | undefined;
        const version = state.blueprintVersion as string | undefined;
        evidence.push({
          file: stateFile,
          detail: `State: action=${action ?? 'unknown'}, blueprint=${version ?? 'unknown'}`,
        });
      } catch {
        evidence.push({ file: stateFile, detail: 'State file exists but unreadable' });
      }
    }

    if (await ctx.fs.access(configFile)) {
      try {
        const raw = await ctx.fs.readFile(configFile);
        const config = JSON.parse(raw) as Record<string, unknown>;
        const provider = config.endpointType as string | undefined;
        evidence.push({
          file: configFile,
          detail: `Inference provider: ${provider ?? 'unknown'}`,
        });
      } catch {
        evidence.push({ file: configFile, detail: 'Config file exists but unreadable' });
      }
    }

    return {
      id: 'CFG-016',
      name: 'NemoClaw Hardening',
      category: 'config',
      severity: 'info',
      passed: true,
      message: 'NemoClaw sandbox hardening is installed',
      evidence,
    };
  },
};
