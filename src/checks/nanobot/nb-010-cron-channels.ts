import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';

export const nb010: CheckModule = {
  id: 'NB-010',
  name: 'Unrestricted Cron Channels',
  category: 'nanobot',
  severity: 'warning',
  description: 'Check if cron jobs can target any channel or recipient without restrictions',
  supportedAgents: ['nanobot'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];
    for (const config of ctx.configs) {
      const cron = config.data.cron ?? config.data.cronJobs ?? config.data.scheduledTasks;
      if (!cron || typeof cron !== 'object') continue;

      const jobs = Array.isArray(cron) ? cron : Object.entries(cron).map(([name, job]) => ({ name, ...(job as object) }));

      for (const job of jobs) {
        const j = job as Record<string, unknown>;
        const name = j.name ?? j.id ?? 'unnamed';
        const targetChannel = j.channel ?? j.targetChannel;
        const allowedRecipients = j.allowedRecipients ?? j.recipients;

        if (!targetChannel && !allowedRecipients) {
          evidence.push({
            file: config.filePath,
            detail: `Cron job "${name}" has no channel or recipient restriction — can target any channel`,
          });
        } else if (targetChannel === '*' || targetChannel === 'all') {
          evidence.push({
            file: config.filePath,
            detail: `Cron job "${name}" targets all channels ("${targetChannel}") — unrestricted broadcast`,
          });
        }
      }
    }
    return {
      id: 'NB-010', name: 'Unrestricted Cron Channels', category: 'nanobot',
      severity: 'warning', passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'All cron jobs have channel/recipient restrictions'
        : 'Cron job(s) found that can target any channel without restrictions',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: true, fixDescription: 'Set explicit channel and recipient restrictions for each cron job',
    };
  },
};
