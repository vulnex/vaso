import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

// Cursor hooks (hooks.json — enterprise/user/project tiers) run arbitrary
// commands on agent lifecycle events (beforeShellExecution, beforeMCPExecution,
// beforeReadFile, …) and are FAIL-OPEN by default: if the hook command errors,
// the guarded action proceeds. Project-level hooks arrive via the repo — a
// supply-chain execution vector (cf. GHSA-pc9j-3qc2-95wv).
export const cur011 = defineCheck({
  id: 'CUR-011',
  name: 'Cursor Hooks Configured Without Fail-Closed',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect hooks.json lifecycle hooks that run commands and are not fail-closed (Cursor hooks default to fail-open)',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (!config.filePath.endsWith('hooks.json')) continue;
      const hooks = config.data.hooks as Record<string, unknown> | undefined;
      if (!hooks || typeof hooks !== 'object') continue;

      for (const [event, entries] of Object.entries(hooks)) {
        const list = Array.isArray(entries) ? entries : [entries];
        for (const entry of list) {
          if (!entry || typeof entry !== 'object') continue;
          const e = entry as Record<string, unknown>;
          const command = typeof e.command === 'string' ? e.command : undefined;
          if (!command) continue;
          const failClosed = e.failClosed === true;
          if (!failClosed) {
            evidence.push({
              file: config.filePath,
              snippet: `${event}: ${command.slice(0, 80)}`,
              detail: 'Hook command runs on agent lifecycle events and is fail-open — if the hook errors, the guarded action proceeds unchecked',
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No fail-open Cursor lifecycle hooks configured',
      failed: (n) => `Found ${n} fail-open lifecycle hook(s) in Cursor hooks.json`,
      fixDescription: 'Set "failClosed": true on guard hooks, and audit hook commands — project-level hooks.json arrives with the repository',
    });
  },
});
