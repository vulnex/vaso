import { join } from 'node:path';
import { defineCheck } from '../../core/check-builder.js';
import { workspaceDir, worldWritable } from './shared.js';

export const nb010 = defineCheck({
  id: 'NB-010',
  name: 'Cron Job Store Writable by Other Users',
  category: 'nanobot',
  severity: 'warning',
  description: 'nanobot\'s scheduler runs the jobs in <workspace>/cron/jobs.json (legacy: ~/.nanobot/cron/jobs.json) as agent turns — each payload message is executed with the agent\'s tools and can deliver results to any channel recipient. A world-writable job store or cron directory lets any local user schedule commands and exfiltration as the nanobot user.',
  supportedAgents: ['nanobot'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const cronDir = join(workspaceDir(ctx), 'cron');
    const legacyDir = join(ctx.installation.installDir, 'cron');
    const evidence = await worldWritable(ctx, [
      { path: join(cronDir, 'jobs.json'), what: 'The cron job store' },
      { path: cronDir, what: 'The cron directory (jobs.json can be replaced)' },
      { path: join(legacyDir, 'jobs.json'), what: 'The legacy cron job store (migrated on startup)' },
      { path: legacyDir, what: 'The legacy cron directory' },
    ]);
    return h.fromEvidence(evidence, {
      passed: 'Cron job store is not writable by other users',
      failed: (n) => `${n} cron location(s) writable by other local users — scheduled agent turns can be injected`,
      fixDescription: 'chmod 700 <workspace>/cron and chmod 600 <workspace>/cron/jobs.json',
    });
  },
});
