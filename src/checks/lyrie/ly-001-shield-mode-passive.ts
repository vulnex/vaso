import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { envString, lyrieEnvConfigs } from './env.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

const VALID_MODES = new Set(['passive', 'active', 'strict']);

/**
 * LYRIE_SHIELD_MODE is validated by packages/core/src/config.ts (zod enum
 * passive|active|strict — any other value makes startup fail) but, as of
 * 3.4.0, the parsed value is never handed to ShieldManager: both boot paths
 * construct it without a config, so it always runs "active". A passive
 * setting is therefore a latent downgrade (it records the operator's intent
 * and takes effect as soon as upstream wires it), reported as info.
 */
export const ly001 = defineCheck({
  id: 'LY-001',
  name: 'Lyrie Shield Mode Set to Passive',
  category: 'lyrie',
  severity: 'info',
  description: 'Detect LYRIE_SHIELD_MODE=passive (or an invalid value) in the checkout .env. Passive means "log threats, never block". Lyrie 3.4.0 parses the setting but does not pass it to ShieldManager (which always runs "active"), so passive is a latent downgrade that takes effect once upstream wires it; values other than passive/active/strict make Lyrie refuse to start.',
  supportedAgents: ['lyrie'],

  fixTargets: configFixTargets,

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of lyrieEnvConfigs(ctx.configs)) {
      const mode = envString(config, 'LYRIE_SHIELD_MODE')?.toLowerCase();
      if (mode === 'passive') {
        evidence.push({
          file: config.filePath,
          snippet: 'LYRIE_SHIELD_MODE=passive',
          detail: 'Shield configured to log threats without blocking (not yet enforced by Lyrie 3.4.0, which always runs the Shield in "active" mode)',
        });
      } else if (mode && !VALID_MODES.has(mode)) {
        evidence.push({
          file: config.filePath,
          snippet: `LYRIE_SHIELD_MODE=${mode}`,
          detail: 'Invalid Shield mode — Lyrie config validation rejects it and the agent will not start',
        });
      }
    }
    return h.fromEvidence(evidence, {
      passed: 'Shield mode is active, strict, or unset (default active)',
      failed: () => 'LYRIE_SHIELD_MODE is set to passive or an invalid value',
      fixable: true,
      fixDescription: 'Set LYRIE_SHIELD_MODE=active (or strict) in the checkout .env',
    });
  },

  async fix(ctx) {
    const affected = lyrieEnvConfigs(ctx.configs).filter(c => {
      const mode = envString(c, 'LYRIE_SHIELD_MODE')?.toLowerCase();
      return !!mode && mode !== 'active' && mode !== 'strict';
    });
    return fixFirstConfig(affected, {
      checkId: 'LY-001',
      env: 'LYRIE_SHIELD_MODE',
      value: 'active',
      message: 'Set LYRIE_SHIELD_MODE=active',
      noConfigMessage: 'No .env with a passive/invalid LYRIE_SHIELD_MODE found',
    });
  },
});
