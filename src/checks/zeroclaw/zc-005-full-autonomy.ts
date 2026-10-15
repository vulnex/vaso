import { envNote } from '../../adapters/env-overrides.js';
import { defineCheck } from '../../core/check-builder.js';
import type { Evidence } from '../../core/types.js';
import { effectiveProfiles, hasWildcard, mainConfig, profileLabel, writeMainConfig } from './zc-config.js';

function isFull(level: unknown): boolean {
  return typeof level === 'string' && level.trim().toLowerCase() === 'full';
}

export const zc005 = defineCheck({
  id: 'ZC-005',
  name: 'Full Autonomy Risk Profile',
  category: 'zeroclaw',
  severity: 'critical',
  description:
    'Detect a risk profile bound to an enabled agent with level = "full" (the `yolo` preset) — every tool call not in always_ask runs without approval',
  supportedAgents: ['zeroclaw'],

  async run(ctx, h) {
    const config = mainConfig(ctx.configs);
    if (!config) return h.passed('No ZeroClaw config.toml found');
    const evidence: Evidence[] = [];
    for (const p of effectiveProfiles(config.data)) {
      if (!isFull(p.profile.level)) continue;
      if (hasWildcard(p.profile.always_ask)) continue; // always_ask "*" still prompts for everything
      evidence.push({
        file: config.filePath,
        detail: `${profileLabel(p)}: level = "full"${envNote(config.data, `${p.path}.level`)} — tool calls bypass the approval gate`,
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'No agent runs under a full-autonomy risk profile',
      failed: (n) => `${n} risk profile(s) grant full autonomy — approval gates bypassed`,
      fixable: true,
      fixDescription: 'Set level = "supervised" on the affected [risk_profiles.<alias>] (or apply the balanced / locked_down preset)',
    });
  },

  async fix(ctx) {
    const config = mainConfig(ctx.configs);
    const updates: Array<[string, unknown]> = config
      ? effectiveProfiles(config.data)
        .filter(p => isFull(p.profile.level))
        .map(p => [`${p.path}.level`, 'supervised'])
      : [];
    return writeMainConfig(ctx, 'ZC-005', updates, 'Set level="supervised" on full-autonomy risk profiles');
  },
});
