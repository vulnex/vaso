import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isInsecureUrl, markUntrustedProject, mcpServers } from './shared.js';

export const aba007 = defineCheck({
  id: 'ABA-007',
  name: 'Abacus.AI Insecure MCP URL',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Abacus.AI remote MCP servers (http / sse) configured with plaintext http:// URLs to non-loopback hosts',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const { config, server, path } of mcpServers(ctx.configs)) {
      if (!isInsecureUrl(server.url)) continue;
      evidence.push({
        file: config.filePath,
        snippet: `${path}.url: ${server.url}`,
        detail: 'Plaintext http:// MCP endpoint — tool calls, results, headers and OAuth tokens travel unencrypted',
      });
    }

    await markUntrustedProject(ctx, evidence);
    return h.fromEvidence(evidence, {
      passed: 'No Abacus.AI MCP servers use plaintext http:// URLs',
      failed: (n) => `Found ${n} Abacus.AI MCP server(s) with plaintext http:// URLs`,
      fixDescription: 'Switch remote MCP URLs to https:// (loopback http is exempt)',
    });
  },
});
