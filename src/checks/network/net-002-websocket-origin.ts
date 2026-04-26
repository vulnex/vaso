import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const net002 = defineCheck({
  id: 'NET-002',
  name: 'WebSocket Origin Validation',
  category: 'network',
  severity: 'critical',
  description: 'Check if WebSocket connections validate the Origin header (CVE-2026-25253)',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const wsOrigin = getNestedValue(config.data, 'websocket.validateOrigin') ??
                       getNestedValue(config.data, 'ws.checkOrigin') ??
                       getNestedValue(config.data, 'gateway.websocket.origin');

      if (wsOrigin === false || wsOrigin === 'disabled') {
        evidence.push({ file: config.filePath, detail: 'WebSocket origin validation is disabled' });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'WebSocket origin validation is not explicitly disabled',
      failed: () => 'WebSocket origin validation is disabled — vulnerable to cross-origin attacks (CVE-2026-25253)',
    });
  },
});
