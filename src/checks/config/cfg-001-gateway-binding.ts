import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>((curr, key) => {
    if (curr && typeof curr === 'object') return (curr as Record<string, unknown>)[key];
    return undefined;
  }, obj);
}

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
        getNestedValue(config.data, 'host') ??
        config.data.GATEWAY_HOST;

      if (host === '0.0.0.0') {
        evidence.push({
          file: config.filePath,
          detail: `Gateway bound to 0.0.0.0 — accessible from all network interfaces`,
        });
      }

      // Also check raw content for grep-style detection
      if (config.raw.includes('0.0.0.0')) {
        const lines = config.raw.split('\n');
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes('0.0.0.0') && /host|bind|listen/i.test(lines[i])) {
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
};
