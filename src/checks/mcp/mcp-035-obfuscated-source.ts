import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeObfuscation } from '../../analyzers/obfuscation.js';

/**
 * MCP-035 — Obfuscated / Encoded Server Source.
 *
 * A server that decodes a table of base64/hex literals at runtime
 * (`Buffer.from(t[i], 'base64')`, `atob(...)`, `String.fromCharCode(...)`) keeps
 * the strings it actually uses — exfil URLs, hardcoded secrets, shell commands —
 * out of clear text, so static review (VASO's own credential/exfil/env checks
 * included) sees nothing. The encoding has no legitimate purpose in MCP server
 * source; it exists to evade inspection.
 *
 * Two tiers (see `analyzeObfuscation`):
 *  - a decoder operating over a string-table → warning (confirmed string-hiding);
 *  - encoded-data patterns without a qualifying decoder → info (suspicious,
 *    unconfirmed).
 *
 * Source is only available for local servers and — with
 * `vaso mcp scan --resolve-packages` — npm-packaged ones. Surfaced by the
 * appsecco vulnerable-mcp-servers-lab `secrets-pii` server, whose 28-entry
 * base64 table + `_S()` decoder hid its exfil endpoints and previously evaded
 * MCP-003/MCP-032 entirely. arXiv 2503.23278 §5.1 / OWASP MCP04.
 */

export const mcp035 = defineCheck({
  id: 'MCP-035',
  name: 'Obfuscated / Encoded Server Source',
  category: 'mcp',
  severity: 'warning',
  description:
    'Detect MCP server source that hides its real strings (URLs, secrets, commands) behind runtime-decoded base64/hex string-tables, evading static review',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    let sawStringTable = false;

    for (const source of ctx.mcpServerSources ?? []) {
      if (!source.sourceCode) continue;

      const report = analyzeObfuscation(source.sourceCode);
      if (report.tier === 'none') continue;

      const file = source.localPath ?? source.packageName ?? source.serverName;

      if (report.tier === 'string-table') {
        sawStringTable = true;
        evidence.push({
          file,
          snippet: `Server "${source.serverName}"`,
          detail:
            `Encoded string-table obfuscation: ${report.decoderLabels.join(', ')} decodes ` +
            `${report.encodedLiteralCount} encoded literal(s) at runtime — hides the strings the ` +
            `server actually uses (URLs, secrets, commands) from static review`,
        });
        for (const hit of report.hits.slice(0, 5)) {
          evidence.push({ file, line: hit.line, snippet: hit.snippet, detail: hit.label });
        }
      } else {
        // tier === 'encoded' — decoder-less: informational only.
        for (const hit of report.hits.slice(0, 5)) {
          evidence.push({
            file,
            line: hit.line,
            snippet: hit.snippet,
            detail: `${hit.label} (no runtime decoder found — unconfirmed obfuscation)`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No obfuscated/encoded MCP server source detected',
      failed: (n) => `Found ${n} obfuscation indicator(s) in MCP server source`,
      severity: sawStringTable ? 'warning' : 'info',
      fixDescription:
        'Ship MCP server source in clear text; do not decode tables of base64/hex literals at runtime — encoding hides the server’s real behavior (endpoints, secrets, commands) from review',
    });
  },
});
