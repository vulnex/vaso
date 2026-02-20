import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';

function getNestedValue(obj: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>((curr, key) => {
    if (curr && typeof curr === 'object') return (curr as Record<string, unknown>)[key];
    return undefined;
  }, obj);
}

export const cfg015: CheckModule = {
  id: 'CFG-015',
  name: 'mDNS Full Broadcast',
  category: 'config',
  severity: 'info',
  description: 'Check if mDNS/Bonjour is broadcasting full agent info on the local network',

  async run(ctx: ScanContext): Promise<CheckResult> {
    for (const config of ctx.configs) {
      const mdns = getNestedValue(config.data, 'mdns') ??
                   getNestedValue(config.data, 'discovery.mdns') ??
                   getNestedValue(config.data, 'bonjour');

      if (mdns === true || (typeof mdns === 'object' && mdns !== null)) {
        const mdnsObj = typeof mdns === 'object' ? mdns as Record<string, unknown> : {};
        const broadcast = mdnsObj.broadcast ?? mdnsObj.enabled ?? true;
        if (broadcast === true || broadcast === 'full') {
          return {
            id: 'CFG-015',
            name: 'mDNS Full Broadcast',
            category: 'config',
            severity: 'info',
            passed: false,
            message: 'mDNS is broadcasting agent information on the local network',
            evidence: [{ file: config.filePath, detail: 'mDNS/Bonjour broadcasting is enabled' }],
          };
        }
      }
    }

    return {
      id: 'CFG-015',
      name: 'mDNS Full Broadcast',
      category: 'config',
      severity: 'info',
      passed: true,
      message: 'mDNS broadcasting is not enabled',
    };
  },
};
