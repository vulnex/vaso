import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { notCollectedNote } from '../../core/probe-coverage.js';
import { workspaceDir, worldWritable } from './shared.js';

export const nb007 = defineCheck({
  id: 'NB-007',
  name: 'Prompt Files Writable by Other Users',
  category: 'nanobot',
  severity: 'critical',
  description: 'nanobot builds every system prompt from workspace files — AGENTS.md, SOUL.md, USER.md and memory/MEMORY.md — and loads skills from <workspace>/skills and plugins/. If any of them (or their directories) is world-writable, any local user can plant persistent instructions or skills that run with the agent\'s tools. The files existing is by design and not a finding.',
  supportedAgents: ['nanobot'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const ws = workspaceDir(ctx);
    const unverified: string[] = [];
    const evidence = await worldWritable(ctx, [
      { path: join(ws, 'AGENTS.md'), what: 'AGENTS.md (system prompt)' },
      { path: join(ws, 'SOUL.md'), what: 'SOUL.md (system prompt)' },
      { path: join(ws, 'USER.md'), what: 'USER.md (system prompt)' },
      { path: join(ws, 'memory', 'MEMORY.md'), what: 'memory/MEMORY.md (long-term memory in the system prompt)' },
      { path: join(ws, 'memory'), what: 'The memory directory' },
      { path: join(ws, 'skills'), what: 'The workspace skills directory' },
      { path: join(ws, 'plugins'), what: 'The workspace plugins directory' },
      { path: ws, what: 'The agent workspace directory (prompt files can be replaced)' },
    ], unverified);
    return h.fromEvidence(evidence, {
      passed: unverified.length > 0 ? `Prompt, memory and skill locations are not writable by other users; ${notCollectedNote('path(s)', unverified)}` : 'Prompt, memory and skill locations are not writable by other users',
      failed: (n) => `${n} prompt/memory/skill location(s) writable by other local users — persistent prompt injection${unverified.length > 0 ? `; ${notCollectedNote('path(s)', unverified)}` : ''}`,
      fixDescription: 'Remove world write access: chmod 700 ~/.nanobot/workspace ~/.nanobot/workspace/{memory,skills,plugins}; chmod 600 the .md files',
    });
  },
});
