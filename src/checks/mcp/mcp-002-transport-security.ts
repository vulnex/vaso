import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

export const mcp002: CheckModule = {
  id: 'MCP-002',
  name: 'Transport Security',
  category: 'mcp',
  severity: 'critical',
  description: 'Check for MCP servers using insecure transports (SSE/HTTP without TLS, binding to 0.0.0.0)',
  supportedAgents: ['mcp'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];

    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        // Check SSE/HTTP servers for TLS
        if (server.url) {
          if (server.url.startsWith('http://') && !server.url.includes('localhost') && !server.url.includes('127.0.0.1')) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${server.url}`,
              detail: 'Non-localhost HTTP transport without TLS — traffic is unencrypted',
            });
          }

          // Check for 0.0.0.0 binding
          if (server.url.includes('0.0.0.0')) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${server.url}`,
              detail: 'Bound to 0.0.0.0 — server is accessible from any network interface',
            });
          }
        }

        // Check command args for insecure flags
        if (server.args) {
          const argsStr = server.args.join(' ');
          if (argsStr.includes('0.0.0.0')) {
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

    return {
      id: 'MCP-002',
      name: 'Transport Security',
      category: 'mcp',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'All MCP transports use secure configurations'
        : `Found ${evidence.length} insecure transport configuration(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
    };
  },
};
