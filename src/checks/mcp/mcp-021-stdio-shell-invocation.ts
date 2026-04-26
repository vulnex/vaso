import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const SHELL_BINS = new Set(['sh', 'bash', 'zsh', 'fish', 'dash', 'ksh']);
const SHELL_EXEC_FLAGS = new Set(['-c', '-cu', '-uc']);

function basename(p: string): string {
  const idx = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return idx >= 0 ? p.slice(idx + 1) : p;
}

export const mcp021 = defineCheck({
  id: 'MCP-021',
  name: 'Stdio Server Shell Invocation',
  category: 'mcp',
  severity: 'warning',
  description: 'Detect stdio MCP servers launched through sh -c / bash -c, which turns any env var or arg into shell input',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const mcpConfigs = ctx.mcpConfigs ?? [];

    for (const config of mcpConfigs) {
      for (const server of config.servers) {
        if (!server.command || !server.args) continue;
        const base = basename(server.command);
        if (!SHELL_BINS.has(base)) continue;
        if (!server.args.some(a => SHELL_EXEC_FLAGS.has(a))) continue;

        evidence.push({
          file: config.filePath,
          snippet: `Server "${server.name}": ${server.command} ${server.args.join(' ')}`,
          detail: `MCP server launched via ${base} -c — any value in env or args is parsed as shell, opening the door to injection`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No MCP servers are launched through a shell -c invocation',
      failed: (n) => `Found ${n} MCP server(s) launched via shell -c — injection-prone`,
      fixDescription: 'Invoke the server binary directly with argv (command: "/path/to/server", args: [...]); avoid shell -c wrappers',
    });
  },
});
