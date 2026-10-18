import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { hookCommandRisks, topTier } from '../../analyzers/hook-commands.js';

// Every hooks.json event runs its command on its own — sessionStart and
// workspaceOpen before the user has typed anything — so what the command does
// matters whether or not the hook gates an action (CUR-011 judges only the
// fail-open gating hooks). Command hooks get the event as JSON on stdin; a
// project .cursor/hooks.json arrives with the repository
// (cursor.com/docs/agent/hooks). `type: "prompt"` hooks run no command.

export const cur015 = defineCheck({
  id: 'CUR-015',
  name: 'Cursor Hook Command Fetches Code or Exfiltrates',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Cursor hooks.json commands (any event, incl. sessionStart) that download and execute code, send credentials or hook input over the network, or re-evaluate input as code',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let critical = false;

    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('hooks.json')) continue;
      const hooks = config.data.hooks as Record<string, unknown> | undefined;
      if (!hooks || typeof hooks !== 'object' || Array.isArray(hooks)) continue;

      for (const [event, entries] of Object.entries(hooks)) {
        for (const entry of Array.isArray(entries) ? entries : [entries]) {
          if (!entry || typeof entry !== 'object') continue;
          const e = entry as Record<string, unknown>;
          if (e.type === 'prompt' || typeof e.command !== 'string') continue;
          const risks = hookCommandRisks(e.command);
          const tier = topTier(risks);
          if (!tier) continue;
          if (tier === 'critical') critical = true;
          evidence.push({
            file: config.filePath,
            snippet: `${event}: ${e.command.slice(0, 120)}`,
            detail: `Hook command ${risks.map(r => r.reason).join('; ')}`,
            ...(tier === 'info' ? { mitigated: true } : {}),
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No Cursor hook command downloads code or sends data out',
      failed: (n) => `Found ${n} Cursor hook command(s) that fetch code or send data over the network`,
      severity: critical ? 'critical' : 'warning',
      fixDescription: 'Remove hooks you did not add yourself (project .cursor/hooks.json arrives with the repo); run vendored, reviewed scripts instead of downloads, and send audit data only to endpoints you control over https',
    });
  },
});
