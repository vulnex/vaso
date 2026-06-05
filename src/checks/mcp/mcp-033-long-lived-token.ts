import type { Evidence } from '../../core/types.js';
import type { MCPServerEntry } from '../../mcp/types.js';
import { defineCheck } from '../../core/check-builder.js';

/**
 * MCP-033 — Long-Lived / Non-Expiring Token.
 *
 * Post-update privilege persistence (Hou et al. arXiv 2503.23278 §5.3.1; OWASP
 * MCP01): a credential that never expires stays valid forever, so a leak or a
 * revoked grant keeps working. Two static signals:
 *  - a JWT access token whose payload has no `exp`, or an `exp` more than a year
 *    out; and
 *  - an opaque hardcoded token with no refresh-token / expiry companion env var.
 */

const TOKEN_ENV_RE = /(access[_-]?token|bearer[_-]?token|^token$|_token$|^bearer$|api[_-]?token)/i;
const REFRESH_OR_EXPIRY_RE = /(refresh[_-]?token|expires|expiry|_exp$|_ttl$|token[_-]?lifetime)/i;
const PLACEHOLDER_RE = /^\$\{?[A-Z0-9_]+\}?$/; // ${VAR} / $VAR — not a literal secret
const ONE_YEAR_SECONDS = 365 * 24 * 60 * 60;

function decodeJwtExp(token: string): { isJwt: boolean; exp?: number } {
  const parts = token.split('.');
  if (parts.length !== 3) return { isJwt: false };
  try {
    const json = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8');
    const payload = JSON.parse(json);
    return { isJwt: true, exp: typeof payload.exp === 'number' ? payload.exp : undefined };
  } catch {
    return { isJwt: false };
  }
}

function analyzeServer(server: MCPServerEntry, nowSeconds: number): Evidence[] {
  const env = server.env ?? {};
  const keys = Object.keys(env);
  const hasRefreshOrExpiry = keys.some((k) => REFRESH_OR_EXPIRY_RE.test(k));
  const evidence: Evidence[] = [];

  for (const [key, rawValue] of Object.entries(env)) {
    if (!TOKEN_ENV_RE.test(key)) continue;
    const value = String(rawValue).trim();
    if (value.length === 0 || PLACEHOLDER_RE.test(value)) continue; // env-ref, not a literal

    const { isJwt, exp } = decodeJwtExp(value);
    if (isJwt) {
      if (exp === undefined) {
        evidence.push({ snippet: `${key}`, file: server.name, detail: `JWT token in ${key} has no expiry (exp) claim — it never expires` });
      } else if (exp - nowSeconds > ONE_YEAR_SECONDS) {
        const when = new Date(exp * 1000).toISOString().slice(0, 10);
        evidence.push({ snippet: `${key}`, file: server.name, detail: `JWT token in ${key} is long-lived (expires ${when}, >1 year out)` });
      }
    } else if (!hasRefreshOrExpiry) {
      evidence.push({ snippet: `${key}`, file: server.name, detail: `Static token in ${key} with no refresh-token or expiry configured — likely a non-rotating long-lived credential` });
    }
  }

  return evidence;
}

export const mcp033 = defineCheck({
  id: 'MCP-033',
  name: 'Long-Lived / Non-Expiring Token',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect MCP server credentials that never expire (JWT without exp / far-future exp, or static tokens with no refresh)',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const evidence: Evidence[] = [];

    for (const config of ctx.mcpConfigs ?? []) {
      for (const server of config.servers) {
        for (const ev of analyzeServer(server, nowSeconds)) {
          evidence.push({ ...ev, file: config.filePath, snippet: `Server "${server.name}": ${ev.snippet}` });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No long-lived or non-expiring MCP server tokens detected',
      failed: (n) => `Found ${n} long-lived / non-expiring MCP server token(s)`,
      fixDescription:
        'Use short-lived tokens with a refresh mechanism (or OAuth with expiry); avoid embedding non-expiring credentials in MCP config',
    });
  },
});
