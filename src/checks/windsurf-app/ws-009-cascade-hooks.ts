import { basename } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { hookCommandRisks, topTier } from '../../analyzers/hook-commands.js';

/**
 * Cascade hooks (docs.devin.ai/desktop/cascade/hooks): hooks.json at system,
 * user (~/.codeium/windsurf/hooks.json) and workspace (.devin/hooks.json, else
 * legacy .windsurf/hooks.json) level — all merged, all run. Each entry's
 * `command` runs through `bash -c` (`powershell` on Windows) on its event
 * (pre_run_command, post_write_code, post_cascade_response_with_transcript, …)
 * with the event JSON on stdin. A workspace file arrives with the repository.
 * Pre-hooks block only on exit 2; any other failure lets the action proceed
 * and there is no fail-closed switch, so that is not reported.
 */
export const ws009 = defineCheck({
  id: 'WS-009',
  name: 'Windsurf Cascade Hook Command Fetches Code or Exfiltrates',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Windsurf / Devin Desktop Cascade hooks.json commands that download and execute code, send credentials or hook input (prompts, code, transcripts) over the network, or re-evaluate input as code',
  supportedAgents: ['windsurf'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let critical = false;

    for (const config of ctx.configs) {
      if (basename(config.filePath) !== 'hooks.json') continue;
      const hooks = config.data.hooks as Record<string, unknown> | undefined;
      if (!hooks || typeof hooks !== 'object' || Array.isArray(hooks)) continue;

      for (const [event, entries] of Object.entries(hooks)) {
        for (const entry of Array.isArray(entries) ? entries : [entries]) {
          if (!entry || typeof entry !== 'object') continue;
          const e = entry as Record<string, unknown>;
          for (const field of ['command', 'powershell'] as const) {
            const script = e[field];
            if (typeof script !== 'string') continue;
            const risks = hookCommandRisks(script);
            const tier = topTier(risks);
            if (!tier) continue;
            if (tier === 'critical') critical = true;
            evidence.push({
              file: config.filePath,
              snippet: `${event}${field === 'powershell' ? ' (powershell)' : ''}: ${script.slice(0, 120)}`,
              detail: `Hook command ${risks.map(r => r.reason).join('; ')}`,
              ...(tier === 'info' ? { mitigated: true } : {}),
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No Cascade hook command downloads code or sends data out',
      failed: (n) => `Found ${n} Cascade hook command(s) that fetch code or send data over the network`,
      severity: critical ? 'critical' : 'warning',
      fixDescription: 'Remove hooks you did not add yourself (a workspace .devin/hooks.json or .windsurf/hooks.json arrives with the repo); run vendored, reviewed scripts instead of downloads, and send audit data only to endpoints you control over https',
    });
  },
});
