import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const DANGEROUS_SCOPE_PATTERNS = [
  { pattern: /scope['":\s]*['"]?\*['"]?/i, detail: 'Wildcard scope — grants unrestricted access' },
  { pattern: /scope['":\s]*['"]?[^'"]*\ball\b/i, detail: 'Scope includes "all" — grants full access' },
  { pattern: /scope['":\s]*['"]?[^'"]*\badmin\b/i, detail: 'Scope includes "admin" — grants administrative access' },
  { pattern: /scope['":\s]*['"]?[^'"]*\broot\b/i, detail: 'Scope includes "root" — grants root-level access' },
  { pattern: /scope['":\s]*['"]?[^'"]*\bfull[_-]?access\b/i, detail: 'Scope includes full-access pattern' },
];

const MAX_SCOPE_COUNT = 10;

export const mcp017: CheckModule = {
  id: 'MCP-017',
  name: 'Overly Broad OAuth Scopes',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect wildcard scopes, excessive scope lists, and full-access patterns in OAuth configurations',
  supportedAgents: ['mcp'],

  async run(ctx: ScanContext): Promise<CheckResult> {
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
      const lines = source.sourceCode.split('\n');
      const filePath = source.localPath ?? source.serverName;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Skip comment lines
        if (line.trim().startsWith('//') || line.trim().startsWith('*')) continue;

        for (const { pattern, detail } of DANGEROUS_SCOPE_PATTERNS) {
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

        // Check for excessive inline scope lists
        const scopeMatch = line.match(/scope['":\s]*['"]([\w\s:,./\-]+)['"]/i);
        if (scopeMatch) {
          const scopes = scopeMatch[1].split(/[\s,]+/).filter(Boolean);
          if (scopes.length > MAX_SCOPE_COUNT) {
            const alreadyCaught = evidence.some(e => e.file === filePath && e.line === i + 1);
            if (!alreadyCaught) {
              evidence.push({
                file: filePath,
                line: i + 1,
                snippet: line.trim(),
                detail: `Excessive scope count (${scopes.length}) — apply principle of least privilege`,
              });
            }
          }
        }
      }
    }

    return {
      id: 'MCP-017',
      name: 'Overly Broad OAuth Scopes',
      category: 'mcp',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'OAuth scopes follow principle of least privilege'
        : `Found ${evidence.length} overly broad OAuth scope pattern(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Request only the minimum scopes needed; avoid wildcards and admin scopes',
    };
  },
};
