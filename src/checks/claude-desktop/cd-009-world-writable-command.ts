import { dirname } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { queryPermissions } from '../../core/permissions.js';
import { notCollectedNote, uncollectedPath } from '../../core/probe-coverage.js';

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
        if (typeof command !== 'string' || !command.startsWith('/')) continue;

        try {
          const perms = await queryPermissions(ctx.fs, command);
          if (perms !== 'unsupported' && perms.worldWrite) {
            // Evidence on the binary itself, not the config (whose own mode
            // other checks report — a shared file would hide that finding)
            evidence.push({
              file: command,
              snippet: `mcpServers.${name}.command = ${command} (mode ${perms.octal})`,
              detail: `MCP command binary (set in ${config.filePath}) is world-writable — any local user can replace it and run code as you`,
            });
            continue;
          }
        } catch {
          // A snapshot doesn't hold a command outside the probe's paths: unknown, not safe
          if (await uncollectedPath(ctx.fs, command)) unverified.push(command);
          continue;
        }

        try {
          const parent = dirname(command);
          const parentPerms = await queryPermissions(ctx.fs, parent);
          if (parentPerms !== 'unsupported' && parentPerms.worldWrite) {
            evidence.push({
              file: parent,
              snippet: `mcpServers.${name}.command = ${command}: ${parent} (mode ${parentPerms.octal})`,
              detail: `Parent directory of MCP command is world-writable — attacker can swap ${command}`,
            });
          }
        } catch {
          // ignore
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
