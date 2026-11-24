import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { truncateSnippet } from '../../core/patterns.js';
import { hookCommandRisks, hookExpansion, topTier } from '../../analyzers/hook-commands.js';
import { commandWords, scriptCommands } from '../../mcp/script-command.js';
import { isPinnedOrLocal, runnerPackage } from '../../mcp/package-pin.js';
import { allHooksOffReason, claudeManagedLocks } from './managed-locks.js';

/**
 * The status line command runs in a shell on every refresh with the session
 * JSON on stdin, like a hook (code.claude.com/docs/en/statusline), so it is
 * judged by the shared hook rules: download-and-execute (critical), sending
 * data out, re-evaluating input as code. `$HOME` and Claude's path
 * placeholders are constant. A package runner (`npx ccstatusline`) without a
 * pinned version runs whatever the registry serves next.
 * `disableAllHooks` also stops the status line (settings schema: "Disable
 * all hooks and statusLine execution"), so a status line it covers is
 * reported as mitigated.
 */
const EXPANSION = hookExpansion(['CLAUDE_PROJECT_DIR', 'CLAUDE_CONFIG_DIR']);

function unpinnedRunners(cmd: string): string[] {
  const out: string[] = [];
  for (const line of cmd.split(/\r?\n/)) {
    for (const command of scriptCommands(line)) {
      const words = commandWords(command);
      if (words.length === 0) continue;
      const pkg = runnerPackage(words[0], words.slice(1));
      if (pkg && !isPinnedOrLocal(pkg)) out.push(`${pkg.runner} ${pkg.spec}`);
    }
  }
  return out;
}

export const cc010 = defineCheck({
  id: 'CC-010',
  name: 'Unsafe Status Line Command',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Claude Code statusLine commands that download and execute code, send data out, re-evaluate input as code, or run an unpinned package',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const locks = await claudeManagedLocks(ctx);

    for (const config of ctx.configs) {
      const sl = config.data.statusLine as Record<string, unknown> | undefined;
      if (!sl || typeof sl !== 'object') continue;

      const cmd = sl.command;
      if (typeof cmd !== 'string') continue;

      const risks = hookCommandRisks(cmd, { expansion: EXPANSION });
      const reasons = risks.map(r => r.reason
        .replace('every time the hook fires', 'every time the status line refreshes')
        .replace(/hook input/g, 'status line input'));
      let tier = topTier(risks);
      for (const runner of unpinnedRunners(cmd)) {
        reasons.push(`runs ${runner} without a pinned version — whatever the registry serves next runs on every refresh`);
        if (tier !== 'critical') tier = 'warning';
      }
      if (!tier) continue;
      const off = tier === 'info' ? undefined : allHooksOffReason(ctx, locks, config.filePath);
      evidence.push({
        file: config.filePath,
        snippet: `statusLine.command: ${truncateSnippet(cmd, 120)}`,
        detail: `Status line command ${reasons.join('; ')}${off ? ` (mitigated: not run — ${off})` : ''}`,
        ...(tier === 'info' || off ? { mitigated: true } : {}),
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'Status line command (if any) looks safe',
      failed: () => 'Status line command may download code or execute untrusted input on every refresh',
      fixDescription: 'Point statusLine.command at a reviewed local script, pin package-runner versions (npx pkg@1.2.3), and avoid curl|sh and eval of input',
    });
  },
});
