import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const cd002 = defineCheck({
  id: 'CD-002',
  name: 'Desktop Config File Permissions',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Verify claude_desktop_config.json is not group/world-readable when it contains MCP env values',
  supportedAgents: ['claude-desktop'],
  supportedPlatforms: ['darwin', 'linux'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      // Only flag perms when the file actually contains potentially-sensitive
      // MCP env material. A bare config with just globalShortcut/extensions
      // is uninteresting permission-wise.
      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      let hasEnv = false;
      if (mcpServers && typeof mcpServers === 'object') {
        for (const server of Object.values(mcpServers)) {
          if (server && typeof server === 'object' && (server as Record<string, unknown>).env) {
            hasEnv = true;
            break;
          }
        }
      }
      if (!hasEnv) continue;

      try {
        const stat = await ctx.fs.stat(config.filePath);
        const mode = stat.mode & 0o777;
        if ((mode & 0o044) !== 0) {
          evidence.push({
            file: config.filePath,
            snippet: `mode ${mode.toString(8)}`,
            detail: 'config holds mcpServers.*.env values and is group/world-readable — any local user can read embedded secrets',
          });
        }
      } catch {
        // stat failed; skip
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'claude_desktop_config.json is not group/world-readable (or holds no env material)',
      failed: (n) => `Found ${n} config file(s) with permissive read perms`,
      fixDescription: 'chmod 600 ~/Library/Application\\ Support/Claude/claude_desktop_config.json',
    });
  },
});
