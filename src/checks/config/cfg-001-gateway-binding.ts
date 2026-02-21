import type { CheckModule, ScanContext, CheckResult, FixResult } from '../../core/types.js';
import { updateConfigValue } from '../../remediation/config-writer.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg001: CheckModule = {
  id: 'CFG-001',
  name: 'Gateway Binding',
  category: 'config',
  severity: 'critical',
  description: 'Check if gateway is bound to 0.0.0.0 (all interfaces), exposing it to the network',

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence = [];

    for (const config of ctx.configs) {
      const host =
        getNestedValue(config.data, 'gateway.host') ??
        getNestedValue(config.data, 'server.host') ??
        getNestedValue(config.data, 'host') ??
        config.data.GATEWAY_HOST;

      const WILDCARD_BINDS = ['0.0.0.0', '[::]', '::'];

      if (typeof host === 'string' && WILDCARD_BINDS.includes(host)) {
        evidence.push({
          file: config.filePath,
          detail: `Gateway bound to ${host} — accessible from all network interfaces`,
        });
      }

      // Also check raw content for grep-style detection
      const hasWildcard = WILDCARD_BINDS.some(w => config.raw.includes(w));
      if (hasWildcard) {
        const lines = config.raw.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const hasMatch = WILDCARD_BINDS.some(w => lines[i].includes(w));
          if (hasMatch && /host|bind|listen/i.test(lines[i])) {
            evidence.push({
              file: config.filePath,
              line: i + 1,
              snippet: lines[i].trim(),
            });
          }
        }
      }
    }

    // Deduplicate by file
    const uniqueEvidence = evidence.filter((e, i, arr) =>
      arr.findIndex(x => x.file === e.file && x.line === e.line) === i
    );

    return {
      id: 'CFG-001',
      name: 'Gateway Binding',
      category: 'config',
      severity: 'critical',
      passed: uniqueEvidence.length === 0,
      message: uniqueEvidence.length === 0
        ? 'Gateway is not bound to 0.0.0.0'
        : 'Gateway is bound to 0.0.0.0 — accessible from all network interfaces',
      evidence: uniqueEvidence.length > 0 ? uniqueEvidence : undefined,
      fixable: true,
      fixDescription: 'Rebind gateway to 127.0.0.1',
    };
  },

  async fix(ctx: ScanContext): Promise<FixResult> {
    for (const config of ctx.configs) {
      const keyPath = config.format === 'env' ? 'GATEWAY_HOST' : 'gateway.host';
      await updateConfigValue(config, keyPath, '127.0.0.1');
      return { checkId: 'CFG-001', applied: true, message: 'Set gateway host to 127.0.0.1' };
    }
    return { checkId: 'CFG-001', applied: false, message: 'No config file found' };
  },
};
