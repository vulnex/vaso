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

      // OpenClaw 2026.x Control UI / WebChat websocket origin policy (2026.9.4
      // schema): allowedOrigins ["*"] "means allow any browser origin", and the
      // DANGEROUS Host-header fallback lets the request's own Host stand in for
      // an allowed origin.
      const controlUi = getNestedValue(config.data, 'gateway.controlUi');
      if (controlUi && typeof controlUi === 'object' && (controlUi as Record<string, unknown>).enabled !== false) {
        const ui = controlUi as Record<string, unknown>;
        if (Array.isArray(ui.allowedOrigins) && ui.allowedOrigins.some(o => typeof o === 'string' && o.trim() === '*')) {
          evidence.push({ file: config.filePath, detail: 'gateway.controlUi.allowedOrigins includes "*" — any browser origin is accepted' });
        }
        if (ui.dangerouslyAllowHostHeaderOriginFallback === true) {
          evidence.push({ file: config.filePath, detail: 'gateway.controlUi.dangerouslyAllowHostHeaderOriginFallback: true — origin checked against the Host header' });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'WebSocket origin validation is not explicitly disabled',
      failed: () => 'WebSocket origin validation is disabled or accepts any origin — vulnerable to cross-origin attacks (CVE-2026-25253)',
    });
  },
});
