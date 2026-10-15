import { defineCheck } from '../../core/check-builder.js';
import { CODING_AGENTS } from '../../core/types.js';
import { getNestedValue } from '../../core/utils.js';

export const cfg015 = defineCheck({
  id: 'CFG-015',
  name: 'mDNS Full Broadcast',
  category: 'config',
  severity: 'info',
  description: 'Check if mDNS/Bonjour is broadcasting full agent info on the local network',
  excludedAgents: CODING_AGENTS,

  async run(ctx, h) {
    for (const config of ctx.configs) {
      const openclawMdns = getNestedValue(config.data, 'discovery.mdns');
      const mdns = getNestedValue(config.data, 'mdns') ??
                   openclawMdns ??
                   getNestedValue(config.data, 'bonjour');

      if (mdns === true || (typeof mdns === 'object' && mdns !== null)) {
        const mdnsObj = typeof mdns === 'object' ? mdns as Record<string, unknown> : {};
        // OpenClaw 2026.x: discovery.mdns.mode = off | minimal | full, and an
        // unset mode is "minimal" (2026.9.4 schema) — only "full" adds cliPath/sshPort.
        const mode = typeof mdnsObj.mode === 'string'
          ? mdnsObj.mode
          : mdns === openclawMdns ? 'minimal' : undefined;
        const broadcast = mode !== undefined
          ? mode.toLowerCase() === 'full'
          : mdnsObj.broadcast ?? mdnsObj.enabled ?? true;
        if (broadcast === true || broadcast === 'full') {
          return h.result({
            passed: false,
            message: 'mDNS is broadcasting agent information on the local network',
            evidence: [{ file: config.filePath, detail: 'mDNS/Bonjour broadcasting is enabled' }],
          });
        }
      }
    }

    return h.passed('mDNS broadcasting is not enabled');
  },
});
