import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUntrustedProject, mcpServers } from './shared.js';

// Host anchored: `https://localhost.evil.example` is not loopback
const LOOPBACK = /^https?:\/\/(?:localhost|127(?:\.\d+){3}|\[::1\])(?:[:/?#]|$)/i;

export function isInsecureUrl(url: unknown): url is string {
  return typeof url === 'string' && /^http:\/\//i.test(url.trim()) && !LOOPBACK.test(url.trim());
}

export const msc006 = defineCheck({
  id: 'MSC-006',
  name: 'Muse Code Insecure MCP URL',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect Meta Muse Code streamable-HTTP MCP servers configured with plaintext http:// URLs to non-loopback hosts',
  supportedAgents: ['muse-code'],

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
      passed: 'No Muse Code MCP servers use plaintext http:// URLs',
      failed: (n) => `Found ${n} Muse Code MCP server(s) with plaintext http:// URLs`,
      fixDescription: 'Switch remote MCP URLs to https:// (loopback http is exempt)',
    });
  },
});
