import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { analyzeObfuscation } from '../../analyzers/obfuscation.js';
import { analysisEvasion } from '../../analyzers/ast-analyzer.js';
import type { RevealedStrings } from '../../analyzers/obfuscation.js';
import { analyzeStringTable } from '../../mcp/string-table.js';

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
    let sawDeepNesting = false;

    for (const source of ctx.mcpServerSources ?? []) {
      if (!source.sourceCode) continue;

      const report = analyzeObfuscation(source.sourceCode);
      // Confirmation comes from what the literals decode to (see
      // string-table.ts): unpadded/url-safe base64, hex, rot13, char codes and
      // Python decoders included, and `atob` beside a few base64-shaped
      // identifiers no longer counts.
      const table = analyzeStringTable(source.sourceCode);
      const file = source.localPath ?? source.packageName ?? source.serverName;

      // Code built to overflow the parser hides itself from MCP-004/005/006
      const evasion = source.language === 'python' ? undefined : analysisEvasion(source.sourceCode, file);
      const deep = evasion?.line;
      if (evasion !== undefined && deep !== undefined) {
        sawDeepNesting = true;
        const text = source.sourceCode.split('\n')[deep - 1]?.trim() ?? '';
        evidence.push({
          file,
          line: deep,
          snippet: text.slice(0, 80) + (text.length > 80 ? '...' : ''),
          detail: evasion.whole
            ? 'The file is nested or chained deeply enough to overflow the JavaScript parser and could not be analysed — only a line-by-line scan for exec and exfiltration calls ran'
            : 'Code nested or chained deeply enough to crash the JavaScript parser (brackets, templates, `?:`/`!` chains) — the statement is skipped by the other MCP source checks',
        });
      }

      if (!table.confirmed && report.tier === 'none') continue;

      if (table.confirmed) {
        sawStringTable = true;
        evidence.push({
          file,
          snippet: `Server "${source.serverName}"`,
          detail:
            `Encoded string-table obfuscation: ${table.decoderLabels.join(', ')} decodes ` +
            `${table.decodedCount} encoded literal(s) at runtime — hides the strings the ` +
            `server actually uses (URLs, secrets, commands) from static review` +
            describeRevealed(table.revealed),
        });
        const lines = source.sourceCode.split('\n');
        for (const line of table.lines) {
          const text = lines[line - 1]?.trim() ?? '';
          evidence.push({ file, line, snippet: text.slice(0, 80) + (text.length > 80 ? '...' : ''), detail: 'Encoded literal decoded at runtime' });
        }
      } else {
        // Decoder-less (or literals that don't decode to text): informational
        // only. A bare atob() decodes runtime data (JWTs, data URLs); with no
        // encoded literals for it to unpack it is not evidence of hidden strings.
        const encodedHits = report.hits.filter((hit) => hit.label !== 'atob() decoding');
        for (const hit of encodedHits.slice(0, 5)) {
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
      severity: sawStringTable || sawDeepNesting ? 'warning' : 'info',
      fixDescription:
        'Ship MCP server source in clear text; do not decode tables of base64/hex literals at runtime — encoding hides the server’s real behavior (endpoints, secrets, commands) from review',
    });
  },
});

/** "; decoded, they include …" — kinds and hosts only, never the hidden values. */
function describeRevealed(revealed: RevealedStrings | undefined): string {
  if (!revealed) return '';
  const parts: string[] = [];
  for (const kind of revealed.secretKinds) parts.push(`a ${kind}`);
  if (revealed.emailDomains.length > 0) {
    parts.push(`${revealed.emailDomains.length === 1 ? 'an email address' : 'email addresses'} at ${revealed.emailDomains.join(', ')} (personal data)`);
  }
  if (revealed.urlHosts.length > 0) {
    const shown = revealed.urlHosts.slice(0, 5).join(', ');
    const more = revealed.urlHosts.length > 5 ? ` and ${revealed.urlHosts.length - 5} more` : '';
    parts.push(`URLs on ${shown}${more}`);
  }
  return parts.length > 0 ? `; decoded, they include ${parts.join('; ')}` : '';
}
