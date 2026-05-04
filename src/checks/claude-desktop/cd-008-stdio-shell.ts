import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const SHELL_BINS = new Set(['sh', 'bash', 'zsh', 'fish', 'dash', 'ksh']);
const SHELL_EXEC_FLAGS = new Set(['-c', '-cu', '-uc']);

function basename(p: string): string {
  const idx = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return idx >= 0 ? p.slice(idx + 1) : p;
}

export const cd008 = defineCheck({
  id: 'CD-008',
  name: 'Stdio MCP via Shell -c',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect stdio MCP servers launched through sh -c / bash -c, where args become shell input',
  supportedAgents: ['claude-desktop'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!mcpServers || typeof mcpServers !== 'object') continue;

      for (const [name, srv] of Object.entries(mcpServers)) {
        if (!srv || typeof srv !== 'object') continue;
        const server = srv as Record<string, unknown>;
        const command = typeof server.command === 'string' ? server.command : undefined;
        if (!command) continue;
        const args = Array.isArray(server.args)
          ? (server.args as unknown[]).filter((a): a is string => typeof a === 'string')
          : [];

        const base = basename(command);
        if (!SHELL_BINS.has(base)) continue;
        if (!args.some(a => SHELL_EXEC_FLAGS.has(a))) continue;

        evidence.push({
          file: config.filePath,
          snippet: `mcpServers.${name}: ${command} ${args.join(' ')}`,
          detail: `MCP server launched via ${base} -c — env vars and args are reparsed as shell, opening the door to injection`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No MCP servers are launched through a shell -c invocation',
      failed: (n) => `Found ${n} MCP server(s) launched via shell -c`,
      fixDescription: 'Invoke the server binary directly with argv (command: "/path/to/server", args: [...]); avoid shell -c wrappers',
    });
  },
});
