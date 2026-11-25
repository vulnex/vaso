import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { truncateSnippet } from '../../core/patterns.js';
import { hookExpansion, hookItemRisks, hookItems, hookSnippet, topTier } from '../../analyzers/hook-commands.js';
import { isProjectHooks, markUntrustedProject, settingsConfig } from './shared.js';

/**
 * Muse Code hooks use the Claude Code shape ({Event: [{matcher, hooks:
 * [{type: "command", command}]}]}) in settings.json `hooks` and in a
 * workspace's .muse/hooks.json; a shell runs each command with the event JSON
 * on stdin. Workspace hooks run only once that directory is trusted
 * (verified: SessionStart / UserPromptSubmit / Stop hooks did not run in an
 * untrusted workspace and did after trust).
 */
const EXPANSION = hookExpansion(['MUSE_PLUGIN_ROOT']);

export const msc007 = defineCheck({
  id: 'MSC-007',
  name: 'Muse Code Hook Command Fetches Code or Exfiltrates',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Meta Muse Code hooks (settings.json hooks, workspace .muse/hooks.json) whose commands download and execute code, send credentials or hook input (prompts, tool input) over the network, or re-evaluate input as code',
  supportedAgents: ['muse-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const criticalItems = new Set<Evidence>();
    const settings = settingsConfig(ctx.configs);
    const files = [...(settings ? [settings] : []), ...ctx.configs.filter(isProjectHooks)];
    for (const config of files) {
      for (const item of hookItems(config.data.hooks)) {
        const risks = hookItemRisks(item, { expansion: EXPANSION });
        const tier = topTier(risks);
        if (!tier) continue;
        const body = item.url ? `http ${truncateSnippet(item.url, 120)}` : truncateSnippet(item.scripts[0] ?? '', 120);
        const e: Evidence = {
          file: config.filePath,
          snippet: hookSnippet(item.event, body, item.matcher ? `(${item.matcher})` : ''),
          detail: `Hook ${risks.map(r => r.reason).join('; ')}`,
          ...(tier === 'info' ? { mitigated: true } : {}),
        };
        if (tier === 'critical') criticalItems.add(e);
        evidence.push(e);
      }
    }
    await markUntrustedProject(ctx, evidence);
    const critical = evidence.some(e => criticalItems.has(e) && !e.mitigated);
    return h.fromEvidence(evidence, {
      passed: 'No Muse Code hook command downloads code, sends data out or runs input as code',
      failed: (n) => `Found ${n} Muse Code hook command(s) that download code, send data over the network or run hook input as code`,
      severity: critical ? 'critical' : 'warning',
      fixDescription: 'Remove hooks you did not add yourself (a workspace .muse/hooks.json arrives with the repository and runs once the folder is trusted); run vendored, reviewed scripts instead of downloads, send audit data only to endpoints you control over https, and never eval or pipe hook input into a shell',
    });
  },
});
