import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const LOCALHOST_EXCEPTIONS = ['localhost', '127.0.0.1', '[::1]'];

function isLocalhostUrl(url: string): boolean {
  return LOCALHOST_EXCEPTIONS.some(host => url.includes(host));
}

const SOURCE_REDIRECT_PATTERNS = [
  { pattern: /redirect_uri['":\s]*['"]?http:\/\/(?!localhost|127\.0\.0\.1|\[::1\])/, detail: 'HTTP redirect_uri (must use HTTPS for OAuth 2.1)' },
  { pattern: /redirect_uri['":\s]*['"]?\*/, detail: 'Wildcard redirect_uri pattern — allows open redirect attacks' },
  { pattern: /redirect_uri['":\s]*['"]?.*\.\./, detail: 'Path traversal in redirect_uri' },
  { pattern: /redirect.*(?:req\.query|req\.params|request\.query|params\.)/, detail: 'User-controlled redirect target — potential open redirect' },
  { pattern: /callback.*(?:req\.query|req\.params|request\.query|params\.).*redirect/, detail: 'User-controlled redirect in callback handler' },
];

export const mcp016: CheckModule = {
  id: 'MCP-016',
  name: 'Insecure Redirect URI',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect HTTP redirect URIs, wildcard patterns, and user-controlled redirect targets in OAuth flows',
  supportedAgents: ['mcp'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    const mcpServerSources = ctx.mcpServerSources ?? [];

    // Config scan: check env vars for HTTP redirect/callback URLs
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.env) continue;

        for (const [key, value] of Object.entries(server.env)) {
          if (/redirect|callback/i.test(key) && value.startsWith('http://') && !isLocalhostUrl(value)) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": ${key}=${value}`,
              detail: 'HTTP redirect/callback URI in env block — must use HTTPS',
            });
          }
        }
      }
    }

    // Source scan: check for insecure redirect patterns in code
    for (const source of mcpServerSources) {
      if (!source.sourceCode) continue;
      const lines = source.sourceCode.split('\n');
      const filePath = source.localPath ?? source.serverName;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Skip comment lines
        if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

        for (const { pattern, detail } of SOURCE_REDIRECT_PATTERNS) {
          if (pattern.test(line)) {
            evidence.push({
              file: filePath,
              line: i + 1,
              snippet: line.trim(),
              detail,
            });
            break;
          }
        }
      }
    }

    return {
      id: 'MCP-016',
      name: 'Insecure Redirect URI',
      category: 'mcp',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'All OAuth redirect URIs are properly secured'
        : `Found ${evidence.length} insecure redirect URI pattern(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: evidence.length > 0,
      fixDescription: 'Use HTTPS redirect URIs with exact-match validation; never allow user-controlled redirects',
    };
  },
};
