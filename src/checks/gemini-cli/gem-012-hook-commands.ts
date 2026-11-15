import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { truncateSnippet } from '../../core/patterns.js';
import { markUntrustedWorkspace } from '../../adapters/folder-trust.js';
import { geminiWorkspaceTrusted } from '../../adapters/gemini.js';
import { hookExpansion, hookItemRisks, hookItems, topTier, hookSnippet } from '../../analyzers/hook-commands.js';

// Hooks in settings.json (`{Event: [{matcher, hooks: [{type: "command",
// command}]}]}`) run with the user's privileges on every matching event,
// the event JSON on stdin; a project .gemini/settings.json brings its own
// (geminicli.com/docs/hooks). Gemini sets these for every hook — paths and
// IDs it chooses itself, never tool or prompt input.
const GEMINI_HOOK_VARIABLES = ['GEMINI_PROJECT_DIR', 'GEMINI_PLANS_DIR', 'GEMINI_SESSION_ID', 'GEMINI_CWD', 'CLAUDE_PROJECT_DIR'];
const EXPANSION = hookExpansion(GEMINI_HOOK_VARIABLES);

export const gem012 = defineCheck({
  id: 'GEM-012',
  name: 'Gemini Hook Command Fetches Code or Exfiltrates',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Gemini CLI settings.json hooks that download and execute code, send credentials or hook input over the network, or re-evaluate input as code',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let critical = false;

    for (const config of ctx.configs) {
      for (const item of hookItems(config.data.hooks)) {
        const risks = hookItemRisks(item, { expansion: EXPANSION });
        const tier = topTier(risks);
        if (!tier) continue;
        if (tier === 'critical') critical = true;
        evidence.push({
          file: config.filePath,
          snippet: hookSnippet(item.event, truncateSnippet(item.url ?? item.scripts[0], 120), item.matcher ? `(${item.matcher})` : ''),
          detail: `Hook command ${risks.map(r => r.reason).join('; ')}`,
          ...(tier === 'info' ? { mitigated: true } : {}),
        });
      }
    }

    // A project's hooks run only in a trusted workspace
    await markUntrustedWorkspace(ctx, evidence, geminiWorkspaceTrusted);

    return h.fromEvidence(evidence, {
      passed: 'No Gemini hook command downloads code, sends data out or runs input as code',
      failed: (n) => `Found ${n} Gemini hook command(s) that download code, send data over the network or run hook input as code`,
      severity: critical ? 'critical' : 'warning',
      fixDescription: 'Remove hooks you did not add yourself (a project .gemini/settings.json arrives with the repo); run reviewed scripts instead of downloads, send audit data only to https endpoints you control, and never eval or pipe hook input into a shell',
    });
  },
});
