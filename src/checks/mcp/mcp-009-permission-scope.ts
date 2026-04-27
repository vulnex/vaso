import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

// Patterns indicating disproportionate resource access in server names/packages
const OVERPRIVILEGED_PATTERNS = [
  { pattern: /\b(?:admin|root|sudo|superuser)\b/i, name: 'Administrative privilege naming' },
  { pattern: /\b(?:all-access|full-access|unrestricted)\b/i, name: 'Unrestricted access claim' },
];

// Source code patterns indicating excessive permissions
const SOURCE_PERMISSION_PATTERNS = [
  { pattern: /chmod\s*\(\s*['"]?(?:0?777|0?666)/i, name: 'World-writable permissions' },
  { pattern: /--privileged/i, name: 'Docker privileged mode' },
  { pattern: /listen\s*\(\s*(?:0|80|443|8080|3000)\s*[,)]/i, name: 'Binding to well-known port' },
  { pattern: /process\.env\.HOME|process\.env\.USERPROFILE/i, name: 'Accessing user home directory' },
  { pattern: /glob\s*\(\s*['"](?:\/|\*\*)/i, name: 'Recursive filesystem globbing from root' },
  { pattern: /readdir(?:Sync)?\s*\(\s*['"](?:\/|~)/i, name: 'Reading root or home directory' },
];

export const mcp009 = defineCheck({
  id: 'MCP-009',
  name: 'Permission Scope',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect MCP servers requesting disproportionate resource access',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];
    const sources = ctx.mcpServerSources ?? [];

    // Check server names for concerning patterns
    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        for (const { pattern, name } of OVERPRIVILEGED_PATTERNS) {
          if (pattern.test(server.name)) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}"`,
              detail: name,
            });
          }
        }

        // Check args for excessive file system scope
        if (server.args) {
          const argsStr = server.args.join(' ');
          if (/(?:^|\s)\/\s|(?:^|\s)~\s/i.test(argsStr) || argsStr.includes('/**')) {
            evidence.push({
              file: config.filePath,
              snippet: `Server "${server.name}": args=${server.args.join(' ')}`,
              detail: 'Server arguments grant access to broad filesystem paths',
            });
          }
        }
      }
    }

    // Check source code for excessive permission patterns
    for (const source of sources) {
      if (!source.sourceCode) continue;

      const lines = source.sourceCode.split('\n');
      for (let i = 0; i < lines.length; i++) {
        for (const { pattern, name } of SOURCE_PERMISSION_PATTERNS) {
          if (pattern.test(lines[i])) {
            evidence.push({
              file: source.localPath ?? source.serverName,
              line: i + 1,
              snippet: lines[i].trim().slice(0, 120),
              detail: name,
            });
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'MCP server permission scopes appear reasonable',
      failed: (n) => `Found ${n} disproportionate permission scope(s)`,
    });
  },
});
