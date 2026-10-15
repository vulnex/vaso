import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isRemotePlaintextUrl, remoteEndpoint } from '../../mcp/remote-endpoint.js';
import { sourceSegments, segmentSnippet } from '../../mcp/source-segments.js';

/** Server code binding a listener to every interface. */
const ALL_INTERFACES_BIND = [
  /\.listen\(\s*[^,()]+,\s*["'`]0\.0\.0\.0["'`]/, // app.listen(PORT, "0.0.0.0")
  /\bhost\s*[:=]\s*["'`]0\.0\.0\.0["'`]/, // { host: '0.0.0.0' }, uvicorn.run(app, host="0.0.0.0")
  /["'`]--host["'`]\s*,\s*["'`]0\.0\.0\.0["'`]/,
];

/** A condition that the code is running in a container. */
const CONTAINER_CONDITION = /docker|container|kubernetes|\bk8s\b|\bpodman\b/i;

/** Any sign the server authenticates callers. */
const AUTH_IN_SOURCE =
  /requireBearerAuth|bearerAuth|verify(?:Access)?Token|TokenVerifier|AuthSettings|BearerAuthBackend|authenticate|passport|jsonwebtoken|jwt\.verify|oauth|basicAuth|x-api-key|api[_-]?key|authorization/i;

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
          if (isRemotePlaintextUrl(url) && plaintextAllowed) {
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

    // Server source (local, --resolve-packages, --source): an HTTP listener on
    // every interface with no authentication anywhere in the code.
    let containerOnly = 0;
    for (const source of ctx.mcpServerSources ?? []) {
      if (!source.sourceCode || AUTH_IN_SOURCE.test(source.sourceCode)) continue;
      const segments = sourceSegments(source.sourceCode);
      const at = segments.findIndex((seg) => ALL_INTERFACES_BIND.some((re) => re.test(seg.text)));
      if (at < 0) continue;
      const bind = segments[at];
      // Only inside a container (`if _is_docker(): host = "0.0.0.0"`): binding
      // every interface is what makes the container's port forwardable; the
      // host-side exposure is the published port's
      const inContainerOnly = CONTAINER_CONDITION.test(bind.text)
        || segments.slice(Math.max(0, at - 3), at).some((seg) => /\bif\b|\?/.test(seg.text) && CONTAINER_CONDITION.test(seg.text));
      if (inContainerOnly) containerOnly++;
      evidence.push({
        file: source.localPath ?? source.packageName ?? source.serverName,
        line: bind.line,
        snippet: segmentSnippet(bind),
        detail: inContainerOnly
          ? `Server "${source.serverName}" listens on every interface (0.0.0.0) when it detects a container, and its code has no authentication — anyone who can reach the published port can call its tools; publish it on 127.0.0.1 only`
          : `Server "${source.serverName}" listens on every network interface (0.0.0.0) and its code has no authentication — anyone who can reach the host can call its tools`,
      });
    }

    return h.fromEvidence(evidence, {
      // Everything found binds every interface only inside a container
      ...(evidence.length > 0 && containerOnly === evidence.length ? { severity: 'warning' as const } : {}),
      passed: 'All MCP transports use secure configurations',
      failed: (n) => `Found ${n} insecure transport configuration(s)`,
    });
  },
});
