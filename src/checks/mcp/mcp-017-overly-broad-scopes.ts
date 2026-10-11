import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { sourceSegments } from '../../mcp/source-segments.js';

/** Value tests applied to an OAuth scope string (not to the whole line). */
const DANGEROUS_SCOPE_VALUES = [
  { pattern: /(?:^|[\s,+])\*(?:$|[\s,+])/, detail: 'Wildcard scope — grants unrestricted access' },
  { pattern: /\ball\b/i, detail: 'Scope includes "all" — grants full access' },
  { pattern: /\badmin\b/i, detail: 'Scope includes "admin" — grants administrative access' },
  { pattern: /\broot\b/i, detail: 'Scope includes "root" — grants root-level access' },
  { pattern: /\bfull[_-]?access\b/i, detail: 'Scope includes full-access pattern' },
];

/**
 * OAuth scope values in source: `scope: "…"` / `scopes = '…'` / `scope = […]`
 * and `?scope=…` / `&scope=…` in a URL. Matching only the value keeps
 * `const [project, scope] = …` or prose about "Resource Type and Scope" out.
 */
const SCOPE_VALUE = /\bscopes?["']?\s*[:=]\s*(?:["'`]([^"'`]*)["'`]|\[([^\]]*)\])|[?&]scope=([^&"'`\s]*)/gi;

function scopeValues(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(SCOPE_VALUE)) {
    const raw = m[1] ?? m[2] ?? m[3] ?? '';
    let value = raw.replace(/\+/g, ' ');
    try {
      value = decodeURIComponent(value);
    } catch {
      // malformed %-escape — judge the raw text
    }
    out.push(value.replace(/["'`]/g, ''));
  }
  return out;
}


const MAX_SCOPE_COUNT = 10;

export const mcp017 = defineCheck({
  id: 'MCP-017',
  name: 'Overly Broad OAuth Scopes',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect wildcard scopes, excessive scope lists, and full-access patterns in OAuth configurations',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    const mcpServerSources = ctx.mcpServerSources ?? [];

    // Config scan: check env vars named *SCOPE* for dangerous values
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.env) continue;

        for (const [key, value] of Object.entries(server.env)) {
          if (!/scope/i.test(key)) continue;

          // Check for wildcard/admin/full-access
          if (/^\*$|^all$|admin|root|full[_-]?access/i.test(value)) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${key}=${value}`,
              detail: 'Overly broad OAuth scope in env block',
            });
          }

          // Check for excessive scope count
          const scopes = value.split(/[\s,]+/).filter(Boolean);
          if (scopes.length > MAX_SCOPE_COUNT) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${key}= (${scopes.length} scopes)`,
              detail: `Excessive scope count (${scopes.length}) — apply principle of least privilege`,
            });
          }
        }
      }
    }

    // Source scan: check for broad scope patterns in code
    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const segments = sourceSegments(source.sourceCode);
      const filePath = source.localPath ?? source.serverName;

      for (let i = 0; i < segments.length; i++) {
        const line = segments[i].text;

        // Skip comment lines
        if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

        const broad = scopeValues(line)
          .flatMap((value) => DANGEROUS_SCOPE_VALUES.filter(({ pattern }) => pattern.test(value)))
          .at(0);
        if (broad) {
          evidence.push({
            file: filePath,
            line: segments[i].line,
            snippet: line.trim().slice(0, 120),
            detail: broad.detail,
          });
        }

        // Check for excessive inline scope lists
        const scopeMatch = line.match(/scope['":\s]*['"]([\w\s:,./\-]+)['"]/i);
        if (scopeMatch) {
          const scopes = scopeMatch[1].split(/[\s,]+/).filter(Boolean);
          if (scopes.length > MAX_SCOPE_COUNT) {
            const alreadyCaught = evidence.some(e => e.file === filePath && e.line === i + 1);
            if (!alreadyCaught) {
              evidence.push({
                file: filePath,
                line: segments[i].line,
                snippet: line.trim().slice(0, 120),
                detail: `Excessive scope count (${scopes.length}) — apply principle of least privilege`,
              });
            }
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'OAuth scopes follow principle of least privilege',
      failed: (n) => `Found ${n} overly broad OAuth scope pattern(s)`,
      fixable: false,
      fixDescription: 'Request only the minimum scopes needed; avoid wildcards and admin scopes',
    });
  },
});
