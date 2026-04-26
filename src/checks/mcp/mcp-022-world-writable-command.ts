import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const WORLD_WRITABLE_PREFIXES = ['/tmp/', '/var/tmp/', '/private/tmp/'];

const INTERPRETERS = new Set([
  'python', 'python2', 'python3',
  'node', 'nodejs',
  'ruby', 'perl', 'php',
  'sh', 'bash', 'zsh', 'fish', 'dash', 'ksh',
  'deno', 'bun',
]);

function basename(p: string): string {
  const idx = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return idx >= 0 ? p.slice(idx + 1) : p;
}

function inWorldWritable(path: string): string | undefined {
  for (const prefix of WORLD_WRITABLE_PREFIXES) {
    if (path.startsWith(prefix)) return prefix.replace(/\/$/, '');
  }
  return undefined;
}

export const mcp022 = defineCheck({
  id: 'MCP-022',
  name: 'Server Command in World-Writable Path',
  category: 'mcp',
  severity: 'critical',
  description: 'Detect MCP servers whose command (or interpreter script) lives in /tmp, /var/tmp, or /private/tmp — replaceable by any local user',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];

    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.command) continue;

        const cmdDir = inWorldWritable(server.command);
        if (cmdDir) {
          evidence.push({
            file: config.filePath,
            snippet: `Server "${server.name}": ${server.command}`,
            detail: `Server binary lives under ${cmdDir} — any local user can replace it before the next MCP launch`,
          });
          continue;
        }

        // For interpreters (python, node, etc.), check the script path in args[0]
        const base = basename(server.command);
        if (INTERPRETERS.has(base) && server.args && server.args.length > 0) {
          const scriptArg = server.args.find(a => !a.startsWith('-'));
          if (scriptArg) {
            const argDir = inWorldWritable(scriptArg);
            if (argDir) {
              evidence.push({
                file: config.filePath,
                snippet: `Server "${server.name}": ${server.command} ${scriptArg}`,
                detail: `Interpreter runs script under ${argDir} — any local user can swap the script payload`,
              });
            }
          }
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No MCP servers run from world-writable paths',
      failed: (n) => `Found ${n} MCP server(s) running from world-writable paths`,
      fixDescription: 'Move the server binary or script to a user-owned directory (e.g. ~/.local/bin or a project venv); never run from /tmp',
    });
  },
});
