import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { shannonEntropy } from '../../analyzers/entropy.js';

const SECRET_KEY_NAMES = /(?:key|token|secret|pass|api|auth|credential)/i;
const KNOWN_KEY_PREFIXES = [
  /^sk-or-v1-[A-Za-z0-9]{32,}/,
  /^sk-ant-[A-Za-z0-9_-]{20,}/,
  /^sk-[A-Za-z0-9]{20,}/,
  /^ghp_[A-Za-z0-9]{20,}/,
  /^gho_[A-Za-z0-9]{20,}/,
  /^xox[baprs]-[A-Za-z0-9-]{10,}/,
  /^AIza[0-9A-Za-z_-]{30,}/, // Google API key
];
const HIGH_ENTROPY_THRESHOLD = 4.5;
const ENTROPY_MIN_LENGTH = 20;
const MIN_LENGTH = 8;

/** Windsurf's secret interpolation forms — the safe way to reference secrets,
 *  also inside a larger value (`Bearer ${env:TOKEN}`). */
const INTERPOLATION = /\$\{(?:env|file):[^}]*\}/g;
const AUTH_SCHEME = /^\s*(?:Bearer|Basic|Token)\b\s*/i;

/** What is stored on disk once interpolations and an auth scheme are removed. */
function literalPart(value: string): string {
  return value.replace(INTERPOLATION, '').replace(AUTH_SCHEME, '').trim();
}

function isPlaceholder(value: string): boolean {
  if (/^(?:true|false|null)$/i.test(value)) return true;
  if (/^\d+(?:\.\d+)?$/.test(value)) return true;
  if (/^<[^>]*>$/.test(value)) return true;
  if (/your[_-]?|changeme|change[_-]me|replace[_-]?|placeholder|example|xxxx/i.test(value)) return true;
  // Generic env-var references ($VAR, ${VAR}) are not literal secrets.
  if (value.startsWith('$')) return true;
  return false;
}

function isLiteralSecret(key: string, raw: string): boolean {
  const value = literalPart(raw);
  if (value.length < MIN_LENGTH) return false;
  if (isPlaceholder(value)) return false;
  if (KNOWN_KEY_PREFIXES.some(p => p.test(value))) return true;
  if (SECRET_KEY_NAMES.test(key)) return true;
  return value.length >= ENTROPY_MIN_LENGTH && shannonEntropy(value) > HIGH_ENTROPY_THRESHOLD;
}

function walkRecord(
  record: Record<string, unknown>,
  file: string,
  prefix: string,
  evidence: Evidence[],
): void {
  for (const [key, value] of Object.entries(record)) {
    if (typeof value !== 'string') continue;
    if (!isLiteralSecret(key, value)) continue;
    evidence.push({
      file,
      snippet: `${prefix}${key}=${value.slice(0, 8)}…`,
      detail: 'Literal secret in Windsurf MCP config — use ${env:VAR} or ${file:/path} interpolation instead',
    });
  }
}

export const ws003 = defineCheck({
  id: 'WS-003',
  name: 'Windsurf Plaintext Secrets in MCP Config',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect literal API keys/tokens in mcp_config.json env or headers values instead of ${env:} / ${file:} interpolation',
  supportedAgents: ['windsurf'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const servers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') continue;

      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== 'object') continue;
        const rec = server as Record<string, unknown>;

        const env = rec.env;
        if (env && typeof env === 'object') {
          walkRecord(env as Record<string, unknown>, config.filePath, `mcpServers.${name}.env.`, evidence);
        }
        const headers = rec.headers;
        if (headers && typeof headers === 'object') {
          walkRecord(headers as Record<string, unknown>, config.filePath, `mcpServers.${name}.headers.`, evidence);
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No plaintext secrets detected in Windsurf MCP config',
      failed: (n) => `Found ${n} plaintext secret(s) in Windsurf MCP config`,
      fixDescription: 'Replace literal values with ${env:VAR} or ${file:/path} interpolation in mcp_config.json',
    });
  },
});
