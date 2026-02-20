import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>((curr, key) => {
    if (curr && typeof curr === 'object') return (curr as Record<string, unknown>)[key];
    return undefined;
  }, obj);
}

export const net002: CheckModule = {
  id: 'NET-002',
  name: 'WebSocket Origin Validation',
  category: 'network',
  severity: 'critical',
  description: 'Check if WebSocket connections validate the Origin header (CVE-2026-25253)',

  async run(ctx: ScanContext): Promise<CheckResult> {
    for (const config of ctx.configs) {
      const wsOrigin = getNestedValue(config.data, 'websocket.validateOrigin') ??
                       getNestedValue(config.data, 'ws.checkOrigin') ??
                       getNestedValue(config.data, 'gateway.websocket.origin');

      if (wsOrigin === false || wsOrigin === 'disabled') {
        return {
          id: 'NET-002',
          name: 'WebSocket Origin Validation',
          category: 'network',
          severity: 'critical',
          passed: false,
          message: 'WebSocket origin validation is disabled — vulnerable to cross-origin attacks (CVE-2026-25253)',
          evidence: [{ file: config.filePath, detail: 'WebSocket origin validation is disabled' }],
        };
      }
    }

    return {
      id: 'NET-002',
      name: 'WebSocket Origin Validation',
      category: 'network',
      severity: 'critical',
      passed: true,
      message: 'WebSocket origin validation is not explicitly disabled',
    };
  },
};
