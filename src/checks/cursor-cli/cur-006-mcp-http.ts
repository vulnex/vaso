import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { isPlaintextRemoteUrl } from '../windsurf-app/plaintext-url.js';
import { stripJsonc } from '../../core/jsonc.js';
import { isKnownSecretValue, isSecretNamedValue } from '../../analyzers/secret-values.js';
import { findArgSecrets, findUrlSecrets, headerSecret, maskUrlSecrets } from '../../mcp/config-secrets.js';
import { isPinnedOrLocal, pinProblem, runnerPackage } from '../../mcp/package-pin.js';
import { isDisabledServerConfig } from '../../mcp/disabled.js';
import { truncateSnippet } from '../../core/patterns.js';

const URL_FIELDS = ['url', 'httpUrl', 'sseUrl'];
// Cursor resolves ${env:NAME} (also inside a larger value) in command, args,
// env, url and headers (cursor.com/docs/context/mcp "Config interpolation")
const INTERPOLATION = /\$\{env:[^}]*\}/g;
const AUTH_SCHEME = /^\s*(?:Bearer|Basic|Token)\s+/i;

/** What is stored on disk once interpolations and an auth scheme are removed. */
function literal(value: string): string {
  return value.replace(INTERPOLATION, '').replace(AUTH_SCHEME, '').trim();
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((a): a is string => typeof a === 'string') : [];
}

/**
 * MCP servers in ~/.cursor/mcp.json (or a project's .cursor/mcp.json): remote
 * servers over plaintext HTTP (warning), credentials written into env,
 * headers, argv or the URL instead of ${env:NAME} interpolation (critical),
 * and npx/uvx packages without a pinned version (warning).
 */
export const cur006 = defineCheck({
  id: 'CUR-006',
  name: 'Cursor MCP Server Insecure Config',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP servers in ~/.cursor/mcp.json (or a project .cursor/mcp.json) using http:// rather than https://, plaintext credentials in env/headers/args/url instead of ${env:NAME}, or unpinned npx/uvx packages',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpPath = join(ctx.installation.installDir, 'mcp.json');
    if (!(await ctx.fs.access(mcpPath))) {
      return h.passed('No mcp.json present');
    }

    let parsed: Record<string, unknown>;
    try {
      const raw = await ctx.fs.readFile(mcpPath);
      parsed = JSON.parse(stripJsonc(raw)) as Record<string, unknown>;
    } catch {
      return h.passed('mcp.json could not be parsed');
    }

    const servers = parsed.mcpServers as Record<string, unknown> | undefined;
    if (!servers || typeof servers !== 'object') {
      return h.passed('No MCP servers configured');
    }

    let secrets = 0;
    for (const [name, server] of Object.entries(servers)) {
      if (!server || typeof server !== 'object') continue;
      const obj = server as Record<string, unknown>;
      for (const field of URL_FIELDS) {
        const value = obj[field];
        if (typeof value !== 'string') continue;
        for (const s of findUrlSecrets(value, field)) {
          secrets++;
          evidence.push({
            file: mcpPath,
            snippet: `mcpServers.${name}.${field} = ${truncateSnippet(s.masked, 120)}`,
            detail: `Plaintext ${s.kind} in the MCP server URL — use \${env:NAME} interpolation`,
          });
        }
        // localhost MCP is a common dev pattern with no exposure
        if (!isPlaintextRemoteUrl(value)) continue;
        evidence.push({
          file: mcpPath,
          snippet: `mcpServers.${name}.${field} = ${truncateSnippet(maskUrlSecrets(value), 120)}`,
          detail: 'MCP traffic over plaintext HTTP — bearer tokens in headers traverse unencrypted',
        });
      }

      for (const field of ['env', 'headers'] as const) {
        const map = obj[field];
        if (!map || typeof map !== 'object' || Array.isArray(map)) continue;
        for (const [key, raw] of Object.entries(map as Record<string, unknown>)) {
          if (typeof raw !== 'string') continue;
          const value = literal(raw);
          const kind = field === 'headers'
            ? headerSecret(key, raw.replace(INTERPOLATION, ''))
            : isSecretNamedValue(key, value) || isKnownSecretValue(value) ? `credential in env "${key}"` : undefined;
          if (!kind || value === '') continue;
          secrets++;
          evidence.push({
            file: mcpPath,
            snippet: `mcpServers.${name}.${field}.${key} (literal value, ${value.length} chars)`,
            detail: `Plaintext ${kind} — use \${env:NAME} interpolation and keep the value in the environment`,
          });
        }
      }

      const command = typeof obj.command === 'string' ? obj.command : undefined;
      const args = strings(obj.args);
      for (const s of findArgSecrets(args, command)) {
        secrets++;
        evidence.push({
          file: mcpPath,
          snippet: `mcpServers.${name}.${s.location} = ${truncateSnippet(s.masked, 120)}`,
          detail: `Plaintext ${s.kind} in the MCP server's arguments — visible in the process list; use \${env:NAME}`,
        });
      }

      if (!command || isDisabledServerConfig(server)) continue;
      const pkg = runnerPackage(command, obj.args);
      if (!pkg || isPinnedOrLocal(pkg)) continue;
      evidence.push({
        file: mcpPath,
        snippet: truncateSnippet(`mcpServers.${name}: ${command} ${pkg.spec}`, 160),
        detail: `${pinProblem(pkg)} — whatever version the registry serves runs on every start (supply chain risk)`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'Cursor MCP servers use HTTPS or localhost, keep credentials out of mcp.json and pin their packages',
      failed: (n) => secrets > 0
        ? `Found ${n} Cursor MCP issue(s), including ${secrets} plaintext credential(s) in mcp.json`
        : `Found ${n} Cursor MCP issue(s) (plaintext HTTP or unpinned packages)`,
      severity: secrets > 0 ? 'critical' : 'warning',
      fixDescription: 'Use https:// server URLs, reference credentials as ${env:NAME} (rotate any key already written to mcp.json), and pin npx/uvx packages to an exact version (e.g. pkg@1.2.3)',
    });
  },
});
