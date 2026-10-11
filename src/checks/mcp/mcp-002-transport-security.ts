import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { remoteEndpoint } from '../../mcp/remote-endpoint.js';

export const mcp002 = defineCheck({
  id: 'MCP-002',
  name: 'Transport Security',
  category: 'mcp',
  severity: 'critical',
  description: 'Check for MCP servers using insecure transports (SSE/HTTP without TLS, binding to 0.0.0.0)',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];

    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        // Check SSE/HTTP servers for TLS — a direct `url` or one dialed by a
        // stdio bridge (`npx mcp-remote <url>`, `supergateway --sse <url>`).
        const endpoint = remoteEndpoint(server);
        if (endpoint) {
          const { url, via } = endpoint;
          const through = via ? ` via ${via}` : '';
          // mcp-remote itself refuses plaintext to a non-localhost host unless
          // --allow-http is given, so only that opt-out is a live exposure.
          const plaintextAllowed = via !== 'mcp-remote' || endpoint.allowHttp;
          if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1') && plaintextAllowed) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}"${through}: ${url}`,
              detail: via === 'mcp-remote'
                ? 'Non-localhost HTTP transport without TLS — --allow-http lets mcp-remote send traffic unencrypted'
                : 'Non-localhost HTTP transport without TLS — traffic is unencrypted',
            });
          }

          // Check for 0.0.0.0 binding
          if (url.includes('0.0.0.0')) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}"${through}: ${url}`,
              detail: 'Bound to 0.0.0.0 — server is accessible from any network interface',
            });
          }
        }

        // Check command args for insecure flags. A bridge's URL argument was
        // already judged above; don't report its 0.0.0.0 a second time.
        if (server.args) {
          const argsStr = server.args.join(' ');
          if (argsStr.includes('0.0.0.0') && !endpoint?.via) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": args contain 0.0.0.0`,
              detail: 'Server may be bound to all interfaces via command arguments',
            });
          }
          if (/--no-?tls|--insecure|--disable-ssl/i.test(argsStr)) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": TLS disabled in args`,
              detail: 'TLS explicitly disabled via command-line flags',
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All MCP transports use secure configurations',
      failed: (n) => `Found ${n} insecure transport configuration(s)`,
    });
  },
});
