import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { nearbyText, sourceSegments, withoutStringText } from '../../mcp/source-segments.js';

/** A token *value* in code: a variable/property, not the word in a message. */
const TOKEN_REF = String.raw`\b(?:access_?token|refresh_?token|id_?token|oauth_?token|bearer_?token|token|tokens|bearer)\b`;

const CREDENTIAL_TOKEN_REF = String.raw`\b(?:access_?token|refresh_?token|id_?token|auth_?token|oauth\w*|bearer\w*)\b`;

interface TokenPattern {
  pattern: RegExp;
  detail: string;
  /** Match against the statement with string-literal text blanked. */
  codeOnly?: boolean;
  /** A file write; owner-only permissions (0600) make it a protected cache. */
  fileWrite?: boolean;
}

/** A call to a masking/redaction helper, with simple arguments. */
const MASKED_CALL = /\b\w*(?:mask|redact|sanitiz|obfuscat|scrub)\w*\s*\([^()]{0,200}\)/gi;

const INSECURE_TOKEN_PATTERNS: TokenPattern[] = [
  // `console.log("refreshed access token")` logs a message, not a token.
  { pattern: new RegExp(String.raw`console\.(?:log|info|warn|error|debug)\s*\([^;]*` + TOKEN_REF, 'i'), detail: 'OAuth token logged to console', codeOnly: true },
  // Storage keys are strings, so these match the literal text.
  { pattern: /localStorage\.setItem\s*\(.*(?:token|oauth|bearer)/i, detail: 'OAuth token stored in localStorage (vulnerable to XSS)' },
  { pattern: /sessionStorage\.setItem\s*\(.*(?:token|oauth|bearer)/i, detail: 'OAuth token stored in sessionStorage (vulnerable to XSS)' },
  // A bare `token` written to a file is as often a lock/ownership token; only
  // credential names count here.
  { pattern: new RegExp(String.raw`writeFile(?:Sync)?\s*\([^;]*` + CREDENTIAL_TOKEN_REF, 'i'), detail: 'OAuth token written to file without encryption', codeOnly: true, fileWrite: true },
  // A real query string carrying the token, or a URL builder setting it.
  { pattern: /[?&](?:access_token|refresh_token|id_token|token|bearer)=/, detail: 'OAuth token in URL query parameter' },
  { pattern: /searchParams\.(?:set|append)\s*\(\s*["'`](?:access_token|refresh_token|id_token|token)["'`]/, detail: 'OAuth token in URL query parameter' },
];

/**
 * APIs whose documented (and only) way to authenticate is a token in the
 * query string — a server using them has no header alternative to choose.
 */
const QUERY_AUTH_APIS: Array<{ host: RegExp; vendor: string; source: string }> = [
  // "You must supply a valid access token by using the access_token query parameter in every request."
  { host: /\bapi\.mapbox\.com\b/, vendor: 'Mapbox', source: 'https://docs.mapbox.com/api/overview/' },
];

/** A token reference reduced to a yes/no or a size. */
const PRESENCE_ONLY = new RegExp(
  String.raw`(?:!!?\s*|\btypeof\s+|\bBoolean\(\s*)[\w$.?\[\]'"]+|[\w$.?]+(?:\.length\b|\s*(?:!==?|===?)\s*(?:null|undefined)\b)`,
  'g',
);

/** Owner-only file mode (0o600 / 0600 / 384) set on the write — a protected credential cache. */
const OWNER_ONLY_MODE = /\bmode\s*:\s*(?:0o?600|384)\b|chmod(?:Sync)?\s*\([^)]*,\s*(?:0o?600|384)\s*\)/;


export const mcp014 = defineCheck({
  id: 'MCP-014',
  name: 'Insecure Token Storage',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect OAuth tokens written to files, localStorage, console.log, or passed in query parameters',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpServerSources = ctx.mcpServerSources ?? [];

    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const segments = sourceSegments(source.sourceCode);
      const queryAuthApi = QUERY_AUTH_APIS.find(a => a.host.test(source.sourceCode!));
      const filePath = source.localPath ?? source.serverName;

      for (let i = 0; i < segments.length; i++) {
        const line = segments[i].text;

        // Skip comment lines
        if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

        // `!!session.refresh_token`, `typeof token`, `token.length`, `token
        // != null` log whether a token exists, not the token.
        // A token passed through a masking helper (`maskBearer(token)`,
        // `redact(token)`) is logged masked, not in the clear
        const code = withoutStringText(line).replace(PRESENCE_ONLY, '').replace(MASKED_CALL, '_');
        for (const { pattern, detail, codeOnly, fileWrite } of INSECURE_TOKEN_PATTERNS) {
          if (pattern.test(codeOnly ? code : line)) {
            if (fileWrite && OWNER_ONLY_MODE.test(nearbyText(segments, i, 2))) break;
            const queryAuth = detail === 'OAuth token in URL query parameter' && /access_token/.test(line) ? queryAuthApi : undefined;
            evidence.push({
              file: filePath,
              line: segments[i].line,
              snippet: line.trim().slice(0, 120),
              detail: queryAuth
                ? `Token in URL query parameter — required by the ${queryAuth.vendor} API, which documents no header alternative (${queryAuth.source}); keep these URLs out of logs`
                : detail,
              ...(queryAuth ? { mitigated: true } : {}),
            });
            break; // One finding per line
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No insecure token storage patterns found',
      failed: (n) => `Found ${n} insecure token storage pattern(s)`,
      fixable: false,
      fixDescription: 'Store tokens securely (encrypted at rest, never in logs/URLs/localStorage)',
    });
  },
});
