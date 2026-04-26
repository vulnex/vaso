import type { CheckModule, ScanContext, CheckResult } from '../../core/types.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg015: CheckModule = {
  id: 'CFG-015',
  name: 'mDNS Full Broadcast',
  category: 'config',
  severity: 'info',
  description: 'Check if mDNS/Bonjour is broadcasting full agent info on the local network',
  excludedAgents: CODING_AGENTS,

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
