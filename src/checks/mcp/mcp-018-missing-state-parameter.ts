import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { OAUTH_REQUEST_CONTEXT, isAuthorizeRequest } from '../../mcp/oauth-context.js';
import { sourceSegments, nearbyText, blockText, isStringConstant } from '../../mcp/source-segments.js';

const STATE_PARAM_PATTERN = /state/;
const STATIC_STATE_PATTERN = /state\s*[:=]\s*['"][^'"]*['"]/;
const DYNAMIC_STATE_PATTERNS = [
  /crypto\.random/,
  /uuid/i,
  /Math\.random/,
  /randomBytes/,
  /generateState/i,
  /nonce/i,
];
// Match function definitions or route handlers for callbacks, not URL string values
const CALLBACK_HANDLER_PATTERN = /(?:function\s+\w*[Cc]allback|handle.*[Cc]allback|\.(?:get|post|all)\s*\(\s*['"].*callback)/;
// Comparing state, or (Python) looking it up / rejecting it / handing it to a
// validating callback: `state_mapping.get(state)`, `if not state`, `state in
// pending`, `self.handle_simple_callback(user, pw, state)`.
const STATE_VERIFY_PATTERN = /state.*(?:===|!==|==|!=|verify|check|match|compare|valid)|(?:verify|check|match|compare|valid).*state|\.(?:get|pop)\(\s*["']?\w*state\b|\[\s*\w*state\s*\]|\bstate\w*\s+(?:not\s+)?in\b|\bnot\s+\w*state\b|\w*(?:callback|verify|validate)\w*\([^)]*\bstate\b/i;
/** A thin route that hands the whole request to a handler that does the checking. */
const DELEGATES_REQUEST = /\breturn\s+(?:await\s+)?[\w.]*(?:callback|verify|validate)\w*\(\s*req(?:uest)?\s*\)|\w*(?:callback|verify|validate)\w*\s*\([\s\S]{0,400}?(?:authorization_response\s*=|\b(?:req|request)\.url\b)/i;

// Pattern to detect active URL construction vs config constants
const URL_CONSTRUCTION_PATTERN = /[?&]|URLSearchParams|\.search|\.href|redirect\s*\(|fetch\s*\(|window\.location|\+\s*['"`]|`[^`]*\$\{/;

const SEARCH_RADIUS = 15;

export const mcp018 = defineCheck({
  id: 'MCP-018',
  name: 'Missing State Parameter',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect OAuth authorization flows without state/CSRF protection or with static state values',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpServerSources = ctx.mcpServerSources ?? [];

    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const segments = sourceSegments(source.sourceCode);
      const filePath = source.localPath ?? source.serverName;
      const python = source.language === 'python';

      for (let i = 0; i < segments.length; i++) {
        const line = segments[i].text;

        // Skip comment lines
        if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

        // Detect OAuth authorize URL construction without state
        if (isAuthorizeRequest(line)) {
          // Only flag lines that show active URL construction, not config constants
          const isUrlConstruction = URL_CONSTRUCTION_PATTERN.test(line);
          const isConfigConstant = (/^\s*\w+\s*[:=]\s*['"]https?:\/\//.test(line) && !isUrlConstruction) || isStringConstant(line);

          if (!isConfigConstant) {
            // The request's own block: state is often set further down the
            // same function than a fixed window reaches
            const nearbyCode = `${nearbyText(segments, i, SEARCH_RADIUS)}\n${blockText(segments, i, python)}`;

            if (!STATE_PARAM_PATTERN.test(nearbyCode)) {
              evidence.push({
                file: filePath,
                line: segments[i].line,
                snippet: line.trim().slice(0, 120),
                detail: 'OAuth authorization URL constructed without state parameter — vulnerable to CSRF',
              });
            }
          }
        }

        // Detect hardcoded/static state values
        if (STATIC_STATE_PATTERN.test(line) && /state/.test(line)) {
          const nearbyCode = nearbyText(segments, i, 5);

          const isDynamic = DYNAMIC_STATE_PATTERNS.some(p => p.test(nearbyCode));
          // Only an authorization-request state matters; `state: "finished"`
          // on a queue item or parser result is not OAuth.
          if (!isDynamic && OAUTH_REQUEST_CONTEXT.test(nearbyCode)) {
            evidence.push({
              file: filePath,
              line: segments[i].line,
              snippet: line.trim().slice(0, 120),
              detail: 'Static/hardcoded state value — state must be a unique random value per request',
            });
          }
        }

        // Detect callback handlers that don't verify state
        // (an export list naming the handler isn't the handler)
        if (CALLBACK_HANDLER_PATTERN.test(line) && !/^\s*(?:module\.exports|exports\.\w+|export\s*\{|from\s+\S+\s+import\b|import\b)/.test(line)) {
          // The handler's body, wherever in it the check sits
          const nearbyCode = blockText(segments, i, python);

          if (DELEGATES_REQUEST.test(nearbyCode)) continue;
          if (STATE_PARAM_PATTERN.test(nearbyCode) === false ||
              (STATE_PARAM_PATTERN.test(nearbyCode) && !STATE_VERIFY_PATTERN.test(nearbyCode))) {
            // Only flag if this looks like it's handling an OAuth callback
            // An OAuth callback reads the authorization code or exchanges it;
            // any function named *callback mentioning "code" is not one
            if (/authorization_code|grant_type|access_token|['"]code['"]|\bcode\s*[,}=]|\.code\b/.test(nearbyCode)) {
              evidence.push({
                file: filePath,
                line: segments[i].line,
                snippet: line.trim().slice(0, 120),
                detail: 'OAuth callback handler does not verify state parameter — vulnerable to CSRF',
              });
            }
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'OAuth flows properly implement state/CSRF protection',
      failed: (n) => `Found ${n} OAuth flow(s) without proper state/CSRF protection`,
    });
  },
});
