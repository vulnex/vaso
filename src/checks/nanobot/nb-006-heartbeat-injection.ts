import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { queryPermissions } from '../../core/permissions.js';

export const nb006 = defineCheck({
  id: 'NB-006',
  name: 'HEARTBEAT.md Injection Risk',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check if HEARTBEAT.md exists in workspace and is potentially writable/injectable',
  supportedAgents: ['nanobot'],

  async run(ctx, h) {
    const evidence = [];
    const installDir = ctx.installation.installDir;
    const heartbeatPath = join(installDir, 'workspace', 'HEARTBEAT.md');

    if (await ctx.fs.access(heartbeatPath)) {
      try {
        const perms = await queryPermissions(ctx.fs, heartbeatPath);
        // 'unsupported' → treat as not writable; existence detail below still applies
        const worldWritable = perms !== 'unsupported' && perms.worldWrite;
        const groupWritable = perms !== 'unsupported' && perms.groupWrite;

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

    return h.fromEvidence(evidence, {
      passed: 'No HEARTBEAT.md found in workspace',
      failed: () => 'HEARTBEAT.md present in workspace — potential injection vector',
      fixable: false,
      fixDescription: 'Review HEARTBEAT.md content and set restrictive file permissions (chmod 600)',
    });
  },
});
