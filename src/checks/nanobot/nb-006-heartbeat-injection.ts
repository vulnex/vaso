import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { join } from 'node:path';

export const nb006: CheckModule = {
  id: 'NB-006',
  name: 'HEARTBEAT.md Injection Risk',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check if HEARTBEAT.md exists in workspace and is potentially writable/injectable',
  supportedAgents: ['nanobot'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];
    const installDir = ctx.installation.installDir;
    const heartbeatPath = join(installDir, 'HEARTBEAT.md');

    if (await ctx.fs.access(heartbeatPath)) {
      try {
        const info = await ctx.fs.stat(heartbeatPath);
        const worldWritable = (info.mode & 0o002) !== 0;
        const groupWritable = (info.mode & 0o020) !== 0;

        if (worldWritable) {
          evidence.push({
            file: heartbeatPath,
            detail: 'HEARTBEAT.md is world-writable — any process can inject content',
          });
        } else if (groupWritable) {
          evidence.push({
            file: heartbeatPath,
            detail: 'HEARTBEAT.md is group-writable — other group members can inject content',
          });
        } else {
          evidence.push({
            file: heartbeatPath,
            detail: 'HEARTBEAT.md exists in workspace — content may be loaded by the agent and could be a prompt injection vector',
          });
        }
      } catch {
        evidence.push({
          file: heartbeatPath,
          detail: 'HEARTBEAT.md exists but permissions could not be checked',
        });
      }
    }

    return {
      id: 'NB-006', name: 'HEARTBEAT.md Injection Risk', category: 'nanobot',
      severity: 'warning', passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No HEARTBEAT.md found in workspace'
        : 'HEARTBEAT.md present in workspace — potential injection vector',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false, fixDescription: 'Review HEARTBEAT.md content and set restrictive file permissions (chmod 600)',
    };
  },
};
