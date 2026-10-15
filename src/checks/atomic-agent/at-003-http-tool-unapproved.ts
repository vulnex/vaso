import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';
import type { ParsedConfig } from '../../core/types.js';
import { asRecord, atomicConfigs } from './shared.js';

/**
 * Approval levels ≥ 3 ("home") auto-approve the `http` category: per the
 * approvals docs, http.approvalMode "writes"/"always" prompts "go quiet from
 * level 3" (atomicagent.io/docs/concepts/approvals). Legacy
 * `approvalRequired: false` loads as level 5.
 */
function approvalLevel(config: ParsedConfig): number | undefined {
  const level = getNestedValue(config.data, 'agent.approvalLevel');
  if (typeof level === 'number') return level;
  return getNestedValue(config.data, 'agent.approvalRequired') === false ? 5 : undefined;
}

const HTTP_QUIET_LEVEL = 3;

export const at003 = defineCheck({
  id: 'AT-003',
  name: 'Atomic Agent HTTP Tool Runs Without Approval',
  category: 'atomic-agent',
  severity: 'warning',
  description: 'http.approvalMode "never" (the shipped default) — or any mode under agent.approvalLevel ≥ 3, which auto-approves HTTP — with no http.hostAllowlist: the os.http.request tool sends any method, including POST/PUT with arbitrary bodies, to any public host without confirmation. A prompt-injected turn can exfiltrate data it has read in a single call.',
  supportedAgents: ['atomic-agent'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let fixable = false;
    for (const config of atomicConfigs(ctx.configs)) {
      const http = asRecord(config.data.http);
      if (http?.enabled === false) continue;
      // Absent block/field → the default, "never" (and pre-v25 "writes" files
      // are migrated to "never" on load).
      const mode = typeof http?.approvalMode === 'string' ? http.approvalMode : 'never';
      const level = approvalLevel(config);
      const levelOverrides = level !== undefined && level >= HTTP_QUIET_LEVEL;
      if (mode !== 'never' && !levelOverrides) continue;
      const allowlist = http?.hostAllowlist;
      if (Array.isArray(allowlist) && allowlist.length > 0) continue;
      if (!levelOverrides) fixable = true;
      evidence.push({
        file: config.filePath,
        snippet: `http.approvalMode: "${mode}", http.hostAllowlist: ${allowlist === undefined ? 'unset' : JSON.stringify(allowlist)}${levelOverrides ? `, agent.approvalLevel: ${level}` : ''}`,
        detail: levelOverrides && mode !== 'never'
          ? `Approval level ${level} auto-approves HTTP requests, so http.approvalMode "${mode}" never prompts — every method runs without approval to any host`
          : 'Outbound HTTP requests of every method run without approval to any host — no human check between reading data and sending it out',
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'Atomic Agent HTTP tool is approval-gated or host-restricted',
      failed: () => 'Atomic Agent HTTP tool can send data to any host without approval',
      fixable,
      fixDescription: 'Set http.approvalMode to "writes" (or "always") with agent.approvalLevel 1–2, or restrict http.hostAllowlist to the hosts the agent needs',
    });
  },

  async fix(ctx) {
    // At level ≥ 3 the ladder auto-approves HTTP whatever approvalMode says —
    // writing it would report a fix that changes nothing.
    const overridden = atomicConfigs(ctx.configs).find(c => (approvalLevel(c) ?? 0) >= HTTP_QUIET_LEVEL);
    if (overridden) {
      return {
        checkId: 'AT-003',
        applied: false,
        message: `agent.approvalLevel ${approvalLevel(overridden)} auto-approves HTTP regardless of http.approvalMode — lower agent.approvalLevel to 1–2 or set http.hostAllowlist manually`,
      };
    }
    return fixFirstConfig(atomicConfigs(ctx.configs), {
      checkId: 'AT-003',
      path: 'http.approvalMode',
      value: 'writes',
      message: 'Set http.approvalMode to "writes" — non-GET requests now ask first',
    });
  },
});
