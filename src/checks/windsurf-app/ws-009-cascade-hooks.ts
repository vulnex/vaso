import { basename } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { hookCommandRisks, hookExpansion, topTier, hookSnippet } from '../../analyzers/hook-commands.js';
import { cascadeRemovedNote } from './cascade-removed.js';

/**
 * Cascade hooks (docs.devin.ai/desktop/cascade/hooks): hooks.json at system,
 * user (~/.codeium/windsurf/hooks.json) and workspace (.devin/hooks.json, else
 * legacy .windsurf/hooks.json) level — all merged, all run. On macOS/Linux an
 * entry's `command` runs through `bash -c` and a `powershell`-only entry is
 * skipped; on Windows `powershell` runs through `powershell -Command` and
 * `command` is the fallback when it is absent — so only the script that runs
 * on the scanned host is judged. Each runs on its event (pre_run_command,
 * post_write_code, post_cascade_response_with_transcript, …) with the event
 * JSON on stdin. A workspace file arrives with the repository. Pre-hooks block
 * only on exit 2; any other failure lets the action proceed and there is no
 * fail-closed switch, so that is not reported. $ROOT_WORKSPACE_PATH (set for
 * post_setup_worktree) is a path Cascade chooses, not hook input.
 * From Devin Desktop 3.9.19 on there is no Cascade (hooks have to be migrated
 * to Devin hooks): leftover Cascade hooks never run and are at most info.
 */
const EXPANSION = hookExpansion(['ROOT_WORKSPACE_PATH']);

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
    const windows = ctx.platform === 'win32';

    for (const config of ctx.configs) {
      if (basename(config.filePath) !== 'hooks.json') continue;
      const hooks = config.data.hooks as Record<string, unknown> | undefined;
      if (!hooks || typeof hooks !== 'object' || Array.isArray(hooks)) continue;

      for (const [event, entries] of Object.entries(hooks)) {
        for (const entry of Array.isArray(entries) ? entries : [entries]) {
          if (!entry || typeof entry !== 'object') continue;
          const e = entry as Record<string, unknown>;
          const field = windows && typeof e.powershell === 'string' ? 'powershell' : 'command';
          const script = e[field];
          if (typeof script !== 'string') continue;
          const risks = hookCommandRisks(script, { expansion: EXPANSION });
          const tier = topTier(risks);
          if (!tier) continue;
          if (tier === 'critical') critical = true;
          evidence.push({
            file: config.filePath,
            snippet: hookSnippet(event, script.slice(0, 120), field === 'powershell' ? ' (powershell)' : ''),
            detail: `Hook command ${risks.map(r => r.reason).join('; ')}`,
            ...(tier === 'info' ? { mitigated: true } : {}),
          });
        }
      }
    }

    const removed = cascadeRemovedNote(ctx);
    if (removed) {
      for (const e of evidence) {
        e.detail = `${e.detail} — inactive: ${removed}`;
        e.mitigated = true;
      }
      critical = false;
    }

    return h.fromEvidence(evidence, {
      passed: removed ?? 'No Cascade hook command downloads code, sends data out or runs input as code',
      failed: (n) => `Found ${n} Cascade hook command(s) that download code, send data over the network or run hook input as code`,
      severity: removed ? 'info' : critical ? 'critical' : 'warning',
      fixDescription: 'Remove hooks you did not add yourself (a workspace .devin/hooks.json or .windsurf/hooks.json arrives with the repo); run vendored, reviewed scripts instead of downloads, send audit data only to endpoints you control over https, and never eval or pipe hook input into a shell',
    });
  },
});
