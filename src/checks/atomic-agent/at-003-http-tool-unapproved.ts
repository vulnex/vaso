import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { fixFirstConfig } from '../../remediation/config-writer.js';
import { asRecord, atomicConfigs } from './shared.js';

export const at003 = defineCheck({
  id: 'AT-003',
  name: 'Atomic Agent HTTP Tool Runs Without Approval',
  category: 'atomic-agent',
  severity: 'warning',
  description: 'http.approvalMode "never" (the shipped default) with no http.hostAllowlist — the os.http.request tool sends any method, including POST/PUT with arbitrary bodies, to any public host without confirmation. A prompt-injected turn can exfiltrate data it has read in a single call.',
  supportedAgents: ['atomic-agent'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of atomicConfigs(ctx.configs)) {
      const http = asRecord(config.data.http);
      if (http?.enabled === false) continue;
      // Absent block/field → the default, "never" (and pre-v25 "writes" files
      // are migrated to "never" on load).
      const mode = typeof http?.approvalMode === 'string' ? http.approvalMode : 'never';
      if (mode !== 'never') continue;
      const allowlist = http?.hostAllowlist;
      if (Array.isArray(allowlist) && allowlist.length > 0) continue;
      evidence.push({
        file: config.filePath,
        snippet: `http.approvalMode: "${mode}", http.hostAllowlist: ${allowlist === undefined ? 'unset' : JSON.stringify(allowlist)}`,
        detail: 'Outbound HTTP requests of every method run without approval to any host — no human check between reading data and sending it out',
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'Atomic Agent HTTP tool is approval-gated or host-restricted',
      failed: () => 'Atomic Agent HTTP tool can send data to any host without approval',
      fixable: true,
      fixDescription: 'Set http.approvalMode to "writes" (or "always"), or restrict http.hostAllowlist to the hosts the agent needs',
    });
  },

  async fix(ctx) {
    return fixFirstConfig(atomicConfigs(ctx.configs), {
      checkId: 'AT-003',
      path: 'http.approvalMode',
      value: 'writes',
      message: 'Set http.approvalMode to "writes" — non-GET requests now ask first',
    });
  },
});
