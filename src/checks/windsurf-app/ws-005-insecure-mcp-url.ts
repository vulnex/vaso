import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isPlaintextRemoteUrl } from './plaintext-url.js';

export const ws005 = defineCheck({
  id: 'WS-005',
  name: 'Windsurf Insecure MCP Server URL',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect remote MCP servers configured with plaintext http:// serverUrl (credentials and tool traffic exposed on the wire)',
  supportedAgents: ['windsurf'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const servers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') continue;

      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== 'object') continue;
        // Windsurf's remote-server key is `serverUrl`; the Devin-format
        // mcp_config.json Devin Desktop shares uses `url`.
        const entry = server as Record<string, unknown>;
        // Both keys are judged: an entry may carry either or both
        for (const key of ['serverUrl', 'url'] as const) {
          const serverUrl = entry[key];
          if (typeof serverUrl !== 'string' || !isPlaintextRemoteUrl(serverUrl)) continue;
          evidence.push({
            file: config.filePath,
            snippet: `mcpServers.${name}.${key}: ${serverUrl}`,
            detail: 'Non-loopback MCP server over plaintext HTTP — headers (auth tokens) and tool traffic can be intercepted or tampered with',
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All Windsurf remote MCP server URLs use HTTPS or loopback',
      failed: (n) => `Found ${n} Windsurf MCP server(s) using plaintext http:// URLs`,
      fixDescription: 'Switch serverUrl to https:// (plain http is acceptable only for localhost, 127.0.0.0/8 or [::1])',
    });
  },
});
