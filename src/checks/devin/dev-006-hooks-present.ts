import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { truncateSnippet } from '../../core/patterns.js';
import { hookItemRisks, hookItems, topTier } from '../../analyzers/hook-commands.js';

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
    let critical = false;

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

      // What each hook command does (shared analyzer: CC-003, CUR-015, WS-009)
      for (const item of hookItems(hooks)) {
        const risks = hookItemRisks(item);
        const tier = topTier(risks);
        if (!tier || tier === 'info') continue;
        if (tier === 'critical') critical = true;
        evidence.push({
          file: config.filePath,
          snippet: `${item.event}${item.matcher ? `(${item.matcher})` : ''}: ${truncateSnippet(item.url ?? item.scripts[0], 120)}`,
          detail: `Hook ${risks.map(r => r.reason).join('; ')}`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No Devin lifecycle hooks configured',
      failed: () => critical
        ? 'Devin lifecycle hooks download and run code or send secrets over the network'
        : 'Devin configs define lifecycle hooks — review the commands they run',
      severity: critical ? 'critical' : undefined,
      fixDescription: 'Audit each hook command; remove hooks you did not add yourself, especially from VCS-committed project configs',
    });
  },
});
