import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const LOCALHOST_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0:0:0:0:0:0:0:1']);

const ORIGIN_FLAG_PATTERNS = [
  /--allowed?-origins?/i,
  /--cors-?origins?/i,
  /--origin-allow-?list/i,
  /--trusted-?origins?/i,
  /--host=?(127\.0\.0\.1|localhost|::1)/i,
];

function extractHostname(url: string): string | undefined {
  try {
    const u = new URL(url);
    return u.hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function hasOriginPinning(args: readonly string[]): boolean {
  const joined = args.join(' ');
  return ORIGIN_FLAG_PATTERNS.some(p => p.test(joined));
}

export const mcp023 = defineCheck({
  id: 'MCP-023',
  name: 'Streamable-HTTP Server Without Origin Pinning',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect streamable-HTTP MCP servers reachable on a non-localhost URL with no apparent Origin/host allowlist — DNS-rebinding hardening required by the 2025 MCP spec',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];

    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (server.transport !== 'streamable-http') continue;
        if (!server.url) continue;

        const host = extractHostname(server.url);
        if (!host || LOCALHOST_HOSTS.has(host)) continue;

        if (hasOriginPinning(server.args ?? [])) continue;

        evidence.push({
          file: config.filePath,
          snippet: `Server "${server.name}" (${server.transport}): ${server.url}`,
          detail: `Streamable-HTTP server reachable at "${host}" with no --allowed-origins / --host pin in args. The 2025 MCP spec requires Origin validation and localhost binding to prevent DNS rebinding attacks against local servers; remote servers must validate Origin per spec §6.2`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Streamable-HTTP MCP servers are localhost-bound or carry an explicit origin allowlist',
      failed: (n) => `Found ${n} streamable-HTTP MCP server(s) without visible Origin/host pinning`,
      fixDescription: 'For local servers, pin the URL to 127.0.0.1/localhost. For remote servers, configure an allowed-origins allowlist and enforce Origin validation server-side.',
    });
  },
});
