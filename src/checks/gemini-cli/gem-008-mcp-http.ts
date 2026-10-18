import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUntrustedWorkspace } from '../../adapters/folder-trust.js';
import { geminiWorkspaceTrusted } from '../../adapters/gemini.js';
import { isPlaintextRemoteUrl } from '../windsurf-app/plaintext-url.js';

const URL_FIELDS = ['url', 'httpUrl', 'sseUrl'];

export const gem008 = defineCheck({
  id: 'GEM-008',
  name: 'Gemini MCP Server Over Plaintext HTTP',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP servers configured to use http:// rather than https://',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const servers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') continue;

      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== 'object') continue;
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

    await markUntrustedWorkspace(ctx, evidence, geminiWorkspaceTrusted);

    return h.fromEvidence(evidence, {
      passed: 'All Gemini MCP servers use HTTPS or localhost transports',
      failed: (n) => `Found ${n} Gemini MCP server(s) using plaintext HTTP`,
      fixDescription: 'Switch the server URL to https:// (or move it behind a TLS-terminating proxy)',
    });
  },
});
