import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { serverOffPredicate } from '../../mcp/off-lists.js';
import { markUntrustedWorkspace } from '../../adapters/folder-trust.js';
import { qwenWorkspaceTrusted } from '../../adapters/qwen-code.js';
import { isPlaintextRemoteUrl } from '../windsurf-app/plaintext-url.js';

const URL_FIELDS = ['url', 'httpUrl', 'sseUrl'];

export const qc007 = defineCheck({
  id: 'QC-007',
  name: 'Qwen MCP Server Over Plaintext HTTP',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Qwen MCP servers configured to use http:// rather than https://',
  supportedAgents: ['qwen-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const off = await serverOffPredicate(ctx); // switched-off servers never connect

    for (const config of ctx.configs) {
      const servers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') continue;
      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== 'object' || off(name, server, { filePath: config.filePath })) continue;
        const obj = server as Record<string, unknown>;
        for (const field of URL_FIELDS) {
          const value = obj[field];
          if (typeof value !== 'string') continue;
          // localhost MCP is a common dev pattern with no exposure
          if (!isPlaintextRemoteUrl(value)) continue;
          evidence.push({
            file: config.filePath,
            snippet: `mcpServers.${name}.${field} = ${value}`,
            detail: 'MCP traffic over plaintext HTTP — credentials, tool args, and prompts traverse unencrypted',
          });
        }
      }
    }

    await markUntrustedWorkspace(ctx, evidence, qwenWorkspaceTrusted);

    return h.fromEvidence(evidence, {
      passed: 'All Qwen MCP servers use HTTPS or localhost transports',
      failed: (n) => `Found ${n} Qwen MCP server(s) using plaintext HTTP`,
      fixDescription: 'Switch the server URL to https:// (or move it behind a TLS-terminating proxy)',
    });
  },
});
