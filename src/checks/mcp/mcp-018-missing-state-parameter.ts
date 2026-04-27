import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const AUTHORIZE_URL_PATTERN = /\/authorize|\/authorization/;
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
const STATE_VERIFY_PATTERN = /state.*(?:===|!==|==|!=|verify|check|match|compare)|(?:verify|check|match|compare).*state/i;

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
      const lines = source.sourceCode.split('\n');
      const filePath = source.localPath ?? source.serverName;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Skip comment lines
        if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

        // Detect OAuth authorize URL construction without state
        if (AUTHORIZE_URL_PATTERN.test(line)) {
          // Only flag lines that show active URL construction, not config constants
          const isUrlConstruction = URL_CONSTRUCTION_PATTERN.test(line);
          const isConfigConstant = /^\s*\w+\s*[:=]\s*['"]https?:\/\//.test(line) && !isUrlConstruction;

          if (!isConfigConstant) {
            const start = Math.max(0, i - SEARCH_RADIUS);
            const end = Math.min(lines.length, i + SEARCH_RADIUS + 1);
            const nearbyCode = lines.slice(start, end).join('\n');

            if (!STATE_PARAM_PATTERN.test(nearbyCode)) {
              evidence.push({
                file: filePath,
                line: i + 1,
                snippet: line.trim(),
                detail: 'OAuth authorization URL constructed without state parameter — vulnerable to CSRF',
              });
            }
          }
        }

        // Detect hardcoded/static state values
        if (STATIC_STATE_PATTERN.test(line) && /state/.test(line)) {
          const start = Math.max(0, i - 5);
          const end = Math.min(lines.length, i + 5 + 1);
          const nearbyCode = lines.slice(start, end).join('\n');

          const isDynamic = DYNAMIC_STATE_PATTERNS.some(p => p.test(nearbyCode));
          if (!isDynamic) {
            evidence.push({
              file: filePath,
              line: i + 1,
              snippet: line.trim(),
              detail: 'Static/hardcoded state value — state must be a unique random value per request',
            });
          }
        }

        // Detect callback handlers that don't verify state
        if (CALLBACK_HANDLER_PATTERN.test(line)) {
          const start = i;
          const end = Math.min(lines.length, i + SEARCH_RADIUS + 1);
          const nearbyCode = lines.slice(start, end).join('\n');

          if (STATE_PARAM_PATTERN.test(nearbyCode) === false ||
              (STATE_PARAM_PATTERN.test(nearbyCode) && !STATE_VERIFY_PATTERN.test(nearbyCode))) {
            // Only flag if this looks like it's handling an OAuth callback
            if (/code|authorization_code|grant/.test(nearbyCode)) {
              evidence.push({
                file: filePath,
                line: i + 1,
                snippet: line.trim(),
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
