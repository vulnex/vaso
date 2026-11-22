import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { extractPosture, findDowngrades, mergeConfigData } from './posture.js';
import { containerEnvironment } from '../../adapters/openclaw-bind.js';
import { openclawAgentEntries } from '../config/openclaw-agents.js';

/**
 * OpenClaw's per-agent overrides are `agents.entries.<id>` (earlier 2026.x:
 * `agents.list[]`) in openclaw.json — `sandbox`, `tools.exec` and the rest
 * beat `agents.defaults` / root `tools` for that agent. No release reads a
 * config file from agents/<id>/ (that directory holds the agent's runtime
 * state), so an entry is what can quietly weaken one agent.
 */
export const oc001 = defineCheck({
  id: 'OC-001',
  name: 'Sub-Agent Config Security Downgrade',
  category: 'openclaw',
  severity: 'critical',
  description: 'Detect when an OpenClaw agent entry (agents.entries.<id>) overrides the defaults to weaken security: disable the sandbox or drop tool approval.',
  supportedAgents: ['openclaw'],

  async run(ctx, h) {
    const policyConfigs = ctx.configs.filter(c => c.format !== 'env');
    const entries = openclawAgentEntries(policyConfigs);
    if (entries.length === 0) {
      return h.passed('No agent entries (agents.entries.<id>) override the defaults');
    }

    const inContainer = await containerEnvironment(ctx.fs);
    const merged = mergeConfigData(policyConfigs);
    const base = extractPosture(merged, undefined, inContainer);
    const evidence: Evidence[] = [];
    for (const entry of entries) {
      for (const detail of findDowngrades(base, extractPosture(merged, entry.id, inContainer))) {
        evidence.push({ file: entry.config.filePath, detail: `agents.entries.${entry.id}: ${detail}` });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No agent entry weakens the default security posture',
      failed: (n) => `Agent entries weaken ${n} default security setting${n === 1 ? '' : 's'}`,
    });
  },
});
