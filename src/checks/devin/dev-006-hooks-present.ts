import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

function hookNames(hooks: unknown): string[] {
  if (Array.isArray(hooks)) {
    return hooks.map((entry, i) => {
      if (typeof entry === 'string') return entry;
      if (entry && typeof entry === 'object') {
        const name = (entry as Record<string, unknown>).name
          ?? (entry as Record<string, unknown>).event;
        if (typeof name === 'string') return name;
      }
      return `#${i}`;
    });
  }
  if (hooks && typeof hooks === 'object') {
    return Object.keys(hooks);
  }
  return [];
}

export const dev006 = defineCheck({
  id: 'DEV-006',
  name: 'Devin Lifecycle Hooks Present',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Flag Devin configs defining lifecycle hooks — hooks execute arbitrary commands, and project-level .devin/config.json is VCS-committed (supply-chain vector)',
  supportedAgents: ['devin'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const hooks = config.data.hooks;
      if (hooks === undefined || hooks === null) continue;
      const names = hookNames(hooks);
      if (names.length === 0) continue;

      evidence.push({
        file: config.filePath,
        snippet: `hooks: ${names.join(', ')}`,
        detail: `Config defines ${names.length} lifecycle hook(s) (${names.join(', ')}) — each runs an arbitrary command; a hook added to a committed .devin/config.json executes on every contributor's machine`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'No Devin lifecycle hooks configured',
      failed: (n) => `Found lifecycle hooks in ${n} Devin config(s) — review the commands they run`,
      fixDescription: 'Audit each hook command; remove hooks you did not add yourself, especially from VCS-committed project configs',
    });
  },
});
