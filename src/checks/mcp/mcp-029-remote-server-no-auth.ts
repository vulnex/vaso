import type { Evidence } from '../../core/types.js';
import type { MCPServerEntry } from '../../mcp/types.js';
import { defineCheck } from '../../core/check-builder.js';

/**
 * MCP-029 — Remote Server Without Authentication.
 *
 * A remotely-reachable MCP server (SSE / streamable-HTTP, or any http(s) URL on
 * a non-loopback host) that the client connects to with no credentials at all
 * means anyone who can reach that endpoint can drive the server's tools, and a
 * MITM can impersonate it. OWASP MCP07; SlowMist checklist item 72. Localhost
 * endpoints are out of scope here (DNS-rebinding is MCP-023's job).
 */

const AUTH_ENV_RE =
  /(authorization|auth[_-]?token|access[_-]?token|refresh[_-]?token|id[_-]?token|api[_-]?key|apikey|bearer|oauth|client[_-]?secret|secret|token|password|passwd|credential)/i;

const AUTH_ARG_RE = /^(--header|--auth|--authorization|--token|--bearer|--api-?key|-H)$/i;

const QUERY_TOKEN_KEYS = new Set([
  'token',
  'access_token',
  'api_key',
  'apikey',
  'key',
  'auth',
  'authorization',
]);

function parseUrl(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  return (
    h === 'localhost' ||
    h === '127.0.0.1' ||
    h === '::1' ||
    h.endsWith('.localhost')
  );
}

function hasAuthSignal(server: MCPServerEntry, parsed: URL | null): boolean {
  // 1) Any non-empty auth-shaped env var.
  for (const [key, value] of Object.entries(server.env ?? {})) {
    if (AUTH_ENV_RE.test(key) && String(value).trim().length > 0) return true;
  }

  // 2) Credentials embedded in the URL (user:pass@) or an auth-ish query param.
  if (parsed) {
    if (parsed.username || parsed.password) return true;
    for (const k of parsed.searchParams.keys()) {
      if (QUERY_TOKEN_KEYS.has(k.toLowerCase())) return true;
    }
  }

  // 3) An auth header / token flag passed on the command line.
  if (server.args?.some((a) => AUTH_ARG_RE.test(a))) return true;
  if (server.args?.some((a) => /authorization\s*:/i.test(a) || /bearer\s+/i.test(a))) return true;

  return false;
}

export const mcp029 = defineCheck({
  id: 'MCP-029',
  name: 'Remote Server Without Authentication',
  category: 'mcp',
  severity: 'critical',
  description:
    'Detect remotely-reachable MCP servers (SSE / streamable-HTTP / http(s)) configured with no authentication credentials',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.mcpConfigs ?? []) {
      for (const server of config.servers) {
        const isRemoteTransport = server.transport === 'sse' || server.transport === 'streamable-http';
        const parsed = server.url ? parseUrl(server.url) : null;
        const isHttpUrl = parsed?.protocol === 'http:' || parsed?.protocol === 'https:';

        if (!isRemoteTransport && !isHttpUrl) continue; // stdio / local — out of scope

        // Only flag endpoints we can confirm are non-loopback; a remote
        // transport with no resolvable host gives us nothing to assert.
        if (!parsed) continue;
        if (isLoopbackHost(parsed.hostname)) continue;

        if (hasAuthSignal(server, parsed)) continue;

        evidence.push({
          file: config.filePath,
          snippet: `Server "${server.name}": ${server.transport} ${parsed.origin}`,
          detail: `Remote MCP server "${server.name}" (${parsed.host}) is configured with no authentication — any party that can reach this endpoint can invoke its tools, and a MITM can impersonate it`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All remotely-reachable MCP servers carry authentication credentials',
      failed: (n) => `Found ${n} remote MCP server(s) configured without authentication`,
      fixDescription:
        'Require authentication on the server and supply credentials in the client config (Authorization header or OAuth token); never expose an unauthenticated MCP endpoint off-host',
    });
  },
});
