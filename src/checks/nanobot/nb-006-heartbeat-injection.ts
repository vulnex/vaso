import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { notCollectedNote } from '../../core/probe-coverage.js';
import { getPath, nanobotConfigs, pyBool, workspaceDir, worldWritable } from './shared.js';

export const nb006 = defineCheck({
  id: 'NB-006',
  name: 'HEARTBEAT.md Writable by Other Users',
  category: 'nanobot',
  severity: 'warning',
  description: 'The gateway heartbeat (gateway.heartbeat, every 30 min by default) reads <workspace>/HEARTBEAT.md and runs the tasks it lists as autonomous agent turns with full tool access. A world-writable HEARTBEAT.md (or workspace directory) lets any local user schedule commands as the nanobot user. The file existing is by design and not a finding.',
  supportedAgents: ['nanobot'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const data = nanobotConfigs(ctx.configs)[0]?.data;
    if (pyBool(getPath(data, 'gateway.heartbeat.enabled')) === false) {
      return h.passed('Gateway heartbeat is disabled (gateway.heartbeat.enabled: false)');
    }
    const ws = workspaceDir(ctx);
    const unverified: string[] = [];
    const evidence = await worldWritable(ctx, [
      { path: join(ws, 'HEARTBEAT.md'), what: 'HEARTBEAT.md (periodic autonomous task list)' },
      { path: ws, what: 'The agent workspace directory (HEARTBEAT.md can be replaced)' },
    ], unverified);
    return h.fromEvidence(evidence, {
      passed: unverified.length > 0 ? `HEARTBEAT.md is not writable by other users; ${notCollectedNote('path(s)', unverified)}` : 'HEARTBEAT.md is not writable by other users',
      failed: () => `HEARTBEAT.md can be modified by other local users — injected tasks run autonomously${unverified.length > 0 ? `; ${notCollectedNote('path(s)', unverified)}` : ''}`,
      fixDescription: 'chmod o-w the workspace directory and HEARTBEAT.md (e.g. chmod 700 ~/.nanobot/workspace; chmod 600 ~/.nanobot/workspace/HEARTBEAT.md)',
    });
  },
});
