import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { remoteEndpoint } from '../../mcp/remote-endpoint.js';
import { sourceSegments, segmentSnippet } from '../../mcp/source-segments.js';

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

/**
 * A host on the user's own network. DNS rebinding lets a web page reach
 * these — not a public server, whose Origin handling a client config can't
 * show (the server-source arm below reads it when the code is available).
 */
function isPrivateNetworkHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, '');
  if (/^10\./.test(h) || /^192\.168\./.test(h) || /^169\.254\./.test(h)) return true;
  const m = /^172\.(\d+)\./.exec(h);
  if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return true;
  if (/^f[cd][0-9a-f]{2}:/i.test(h) || /^fe80:/i.test(h)) return true;
  // mDNS / internal names and single-label hosts resolve on the LAN
  return /\.(?:local|lan|internal|home\.arpa|localdomain)$/i.test(h) || (!h.includes('.') && !h.includes(':'));
}

function hasOriginPinning(args: readonly string[]): boolean {
  const joined = args.join(' ');
  return ORIGIN_FLAG_PATTERNS.some(p => p.test(joined));
}

/** Server code that switches off Host/Origin validation (DNS-rebinding protection). */
const PROTECTION_DISABLED = [
  { re: /\bMCP_ALLOWED_HOSTS["'`]?\]?\s*[:=]\s*["'`]\*["'`]/, detail: 'sets MCP_ALLOWED_HOSTS to "*" — a wildcard host allowlist' },
  { re: /\benableDnsRebindingProtection\s*:\s*false\b|\benable_dns_rebinding_protection\s*=\s*False\b/, detail: 'turns DNS-rebinding protection off' },
  { re: /\ballowed_?[Hh]osts\s*[:=]\s*\[\s*["'`]\*["'`]/, detail: 'allows every Host header ("*")' },
  { re: /\ballowed_?[Oo]rigins\s*[:=]\s*\[\s*["'`]\*["'`]/, detail: 'allows every Origin ("*")' },
  { re: /Access-Control-Allow-Origin["'`]?\s*[,:]\s*["'`]\*["'`]/i, detail: 'answers every origin with Access-Control-Allow-Origin: *' },
  { re: /\bcors\(\s*\)/, detail: 'enables cors() with no options, which allows every origin' },
];

export const mcp023 = defineCheck({
  id: 'MCP-023',
  name: 'Streamable-HTTP Server Without Origin Pinning',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect streamable-HTTP MCP servers on the local network with no apparent Origin/host allowlist, and server code that switches Host/Origin validation off — DNS-rebinding hardening required by the 2025 MCP spec',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];

    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        // A direct `url` entry, or one dialed through `npx mcp-remote <url>` /
        // `supergateway --streamableHttp <url>`.
        const endpoint = remoteEndpoint(server);
        if (!endpoint || endpoint.transport !== 'streamable-http') continue;

        const host = extractHostname(endpoint.url);
        if (!host || LOCALHOST_HOSTS.has(host) || !isPrivateNetworkHost(host)) continue;

        if (hasOriginPinning(server.args ?? [])) continue;

        const through = endpoint.via ? ` via ${endpoint.via}` : '';
        evidence.push({
          file: config.filePath,
          snippet: `Server "${server.name}" (${endpoint.transport}${through}): ${endpoint.url}`,
          detail: `Streamable-HTTP server on the local network ("${host}") with no --allowed-origins / --host pin in args. A web page can reach LAN services through DNS rebinding unless the server validates Origin (MCP spec 2025, §6.2) — confirm it does, or bind it to localhost`,
        });
      }
    }

    // Server source: Host/Origin validation explicitly switched off. A web
    // page the user visits can then reach a local server through DNS
    // rebinding, or call a remote one from the browser.
    for (const source of ctx.mcpServerSources ?? []) {
      if (!source.sourceCode) continue;
      for (const seg of sourceSegments(source.sourceCode)) {
        const hit = PROTECTION_DISABLED.find(({ re }) => re.test(seg.text));
        if (!hit) continue;
        evidence.push({
          file: source.localPath ?? source.packageName ?? source.serverName,
          line: seg.line,
          snippet: segmentSnippet(seg),
          detail: `Server "${source.serverName}" ${hit.detail} — Host/Origin validation is what stops a web page from driving the server through DNS rebinding or cross-origin requests`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No LAN streamable-HTTP MCP server without Origin pinning, and no server code disabling Host/Origin validation',
      failed: (n) => `Found ${n} streamable-HTTP MCP server(s) without visible Origin/host pinning`,
      fixDescription: 'For local servers, pin the URL to 127.0.0.1/localhost. For remote servers, configure an allowed-origins allowlist and enforce Origin validation server-side.',
    });
  },
});
