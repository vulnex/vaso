import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { maskUrlSecrets } from '../../mcp/config-secrets.js';
import { isProjectInstall, settingsConfig } from './shared.js';
import { isInsecureUrl } from './msc-006-insecure-mcp-url.js';

const META_HOST = /^https:\/\/(?:[a-z0-9-]+\.)*(?:meta\.ai|meta\.com|facebook\.com)(?::443)?(?:[/?#]|$)/i;
const LOOPBACK = /^https?:\/\/(?:localhost|127(?:\.\d+){3}|\[::1\])(?:[:/?#]|$)/i;

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

export const msc011 = defineCheck({
  id: 'MSC-011',
  name: 'Muse Code Endpoint Redirect',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Meta Muse Code settings that send model traffic or telemetry somewhere other than Meta: endpoint_transport.base_url (the Meta provider endpoint — prompts, code and the Meta credential go there), endpoint_transport.proxy, and telemetry.endpoint / telemetry.proxy over plaintext http',
  supportedAgents: ['muse-code'],

  async run(ctx, h) {
    if (isProjectInstall(ctx)) return h.passed('Endpoints are user-level — evaluated on the user installation');
    const settings = settingsConfig(ctx.configs);
    const evidence: Evidence[] = [];
    let critical = false;
    const transport = record(settings?.data.endpoint_transport);
    const base = transport?.base_url;
    if (settings && typeof base === 'string' && base.trim() && !META_HOST.test(base.trim()) && !LOOPBACK.test(base.trim())) {
      const plain = isInsecureUrl(base);
      if (plain) critical = true;
      evidence.push({
        file: settings.filePath,
        snippet: `endpoint_transport.base_url: ${maskUrlSecrets(base)}`,
        detail: plain
          ? 'Model traffic and the Meta credential go to a non-Meta host over plaintext http'
          : 'Model traffic (prompts, code, tool output) and the Meta credential go to a non-Meta host',
      });
    }
    const proxy = transport?.proxy;
    if (settings && typeof proxy === 'string' && isInsecureUrl(proxy)) {
      evidence.push({
        file: settings.filePath,
        snippet: `endpoint_transport.proxy: ${maskUrlSecrets(proxy)}`,
        detail: 'Model traffic is routed through a plaintext http proxy on another host',
      });
    }
    const telemetry = record(settings?.data.telemetry);
    for (const key of ['endpoint', 'proxy']) {
      const url = telemetry?.[key];
      if (!settings || !isInsecureUrl(url)) continue;
      evidence.push({
        file: settings.filePath,
        snippet: `telemetry.${key}: ${maskUrlSecrets(url)}`,
        detail: 'Telemetry (session metadata) is sent over plaintext http',
      });
    }
    return h.fromEvidence(evidence, {
      passed: 'Muse Code talks to Meta endpoints only',
      failed: (n) => `Found ${n} Muse Code endpoint override(s)`,
      severity: critical ? 'critical' : undefined,
      fixDescription: 'Remove endpoint_transport.base_url / proxy unless they point at infrastructure you control over https; send telemetry over https',
    });
  },
});
