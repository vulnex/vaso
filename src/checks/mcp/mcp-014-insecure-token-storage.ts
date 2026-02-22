import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const INSECURE_TOKEN_PATTERNS = [
  { pattern: /console\.log\s*\(.*(?:token|access_token|refresh_token|bearer)/i, detail: 'OAuth token logged to console' },
  { pattern: /localStorage\.setItem\s*\(.*(?:token|oauth|bearer)/i, detail: 'OAuth token stored in localStorage (vulnerable to XSS)' },
  { pattern: /sessionStorage\.setItem\s*\(.*(?:token|oauth|bearer)/i, detail: 'OAuth token stored in sessionStorage (vulnerable to XSS)' },
  { pattern: /writeFile(?:Sync)?\s*\(.*(?:token|oauth|bearer)/i, detail: 'OAuth token written to file without encryption' },
  { pattern: /(?:access_token|bearer|refresh_token|token).*[?&].*=/, detail: 'OAuth token passed in URL query parameter' },
  { pattern: /[?&](?:access_token|token|bearer)=/, detail: 'OAuth token in URL query parameter' },
  { pattern: /url\s*[\+\`].*(?:token|access_token)/, detail: 'OAuth token interpolated into URL' },
  { pattern: /(?:token|access_token|bearer)\s*\+\s*['"`]/, detail: 'OAuth token concatenated into string (potential URL leak)' },
];

export const mcp014: CheckModule = {
  id: 'MCP-014',
  name: 'Insecure Token Storage',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect OAuth tokens written to files, localStorage, console.log, or passed in query parameters',
  supportedAgents: ['mcp'],

  async run(ctx: ScanContext): Promise<CheckResult> {
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

        for (const { pattern, detail } of INSECURE_TOKEN_PATTERNS) {
          if (pattern.test(line)) {
            evidence.push({
              file: filePath,
              line: i + 1,
              snippet: line.trim(),
              detail,
            });
            break; // One finding per line
          }
        }
      }
    }

    return {
      id: 'MCP-014',
      name: 'Insecure Token Storage',
      category: 'mcp',
      severity: 'critical',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'No insecure token storage patterns found'
        : `Found ${evidence.length} insecure token storage pattern(s)`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Store tokens securely (encrypted at rest, never in logs/URLs/localStorage)',
    };
  },
};
