import { dirname } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const cd009 = defineCheck({
  id: 'CD-009',
  name: 'World-Writable MCP Command Path',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP server command binaries (or their parent dirs) that any local user can replace',
  supportedAgents: ['claude-desktop'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!mcpServers || typeof mcpServers !== 'object') continue;

      for (const [name, srv] of Object.entries(mcpServers)) {
        if (!srv || typeof srv !== 'object') continue;
        const command = (srv as Record<string, unknown>).command;
        if (typeof command !== 'string' || !command.startsWith('/')) continue;

        try {
          const stat = await ctx.fs.stat(command);
          if ((stat.mode & 0o002) !== 0) {
            evidence.push({
              file: config.filePath,
              snippet: `mcpServers.${name}.command = ${command} (mode ${(stat.mode & 0o777).toString(8)})`,
              detail: 'MCP command binary is world-writable — any local user can replace it and run code as you',
            });
            continue;
          }
        } catch {
          continue;
        }

        try {
          const parent = dirname(command);
          const parentStat = await ctx.fs.stat(parent);
          if ((parentStat.mode & 0o002) !== 0) {
            evidence.push({
              file: config.filePath,
              snippet: `${parent} (mode ${(parentStat.mode & 0o777).toString(8)})`,
              detail: `Parent directory of MCP command is world-writable — attacker can swap ${command}`,
            });
          }
        } catch {
          // ignore
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No MCP commands live on world-writable paths',
      failed: (n) => `Found ${n} MCP command(s) on world-writable paths`,
      fixDescription: 'Move MCP command binaries to a non-world-writable location and chmod o-w the parent directory',
    });
  },
});
