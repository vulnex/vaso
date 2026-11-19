import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { notCollectedNote } from '../../core/probe-coverage.js';
import { writableLaunchPaths, writableLaunchText } from '../../mcp/writable-command.js';

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
    const unverified: string[] = [];

    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!mcpServers || typeof mcpServers !== 'object') continue;

      for (const [name, srv] of Object.entries(mcpServers)) {
        if (!srv || typeof srv !== 'object') continue;
        const command = (srv as Record<string, unknown>).command;
        if (typeof command !== 'string') continue;
        const rawArgs = (srv as Record<string, unknown>).args;
        const args = Array.isArray(rawArgs) ? rawArgs.filter((a): a is string => typeof a === 'string') : [];

        // The command, or a script an interpreter command runs. A snapshot
        // without what it takes to judge a path: unknown, not safe
        for (const w of await writableLaunchPaths(ctx.fs, command, args, unverified, { config: config.filePath })) {
          const { where, detail } = writableLaunchText(w);
          // Evidence on the file or directory itself, not the config (whose
          // own mode other checks report — a shared file would hide that finding)
          evidence.push({
            file: w.writable.kind === 'binary' ? w.path : w.writable.path,
            snippet: `mcpServers.${name}.${w.role === 'command' ? 'command' : 'args'} = ${w.path}${where}`,
            detail: `${detail} (set in ${config.filePath})`,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: unverified.length > 0
        ? notCollectedNote('MCP command path(s)', unverified)
        : 'No MCP commands live on world-writable paths',
      failed: (n) => `Found ${n} MCP command(s) on world-writable paths${unverified.length > 0 ? `; ${notCollectedNote('command path(s)', unverified)}` : ''}`,
      fixDescription: 'Move MCP command binaries to a non-world-writable location and chmod o-w the parent directory',
    });
  },
});
