import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import type { ParsedConfig } from '../../core/types.js';
import { markUnreachable, queryPermissions, readableByOthers } from '../../core/permissions.js';
import { restrictFilesToOwner } from '../../remediation/config-writer.js';
import { permissionFixTargets } from '../../remediation/fix-refusal.js';

export const cd002 = defineCheck({
  id: 'CD-002',
  name: 'Desktop Config File Permissions',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Verify claude_desktop_config.json is not group/world-readable when it contains MCP env values',
  supportedAgents: ['claude-desktop'],
  supportedPlatforms: ['darwin', 'linux'],

  fixTargets: permissionFixTargets,

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (!hasEnvMaterial(config)) continue;

      try {
        const perms = await queryPermissions(ctx.fs, config.filePath);
        if (perms !== 'unsupported' && readableByOthers(perms)) {
          evidence.push({
            file: config.filePath,
            snippet: `mode ${perms.octal}`,
            detail: 'config holds mcpServers.*.env values and is group/world-readable — any local user can read embedded secrets',
          });
        }
      } catch {
        // stat failed; skip
      }
    }

    await markUnreachable(ctx.fs, evidence);
    return h.fromEvidence(evidence, {
      passed: 'claude_desktop_config.json is not group/world-readable (or holds no env material)',
      failed: (n) => `Found ${n} config file(s) with permissive read perms`,
      fixable: true,
      fixDescription: 'Remove group/other access from claude_desktop_config.json (chmod go-rwx)',
    });
  },

  async fix(ctx) {
    return restrictFilesToOwner('CD-002', ctx.configs.filter(hasEnvMaterial).map(c => c.filePath));
  },
});

/**
 * Only flag perms when the file actually contains potentially-sensitive MCP
 * env material. A bare config with just globalShortcut/extensions is
 * uninteresting permission-wise.
 */
function hasEnvMaterial(config: ParsedConfig): boolean {
  const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
  if (!mcpServers || typeof mcpServers !== 'object') return false;
  return Object.values(mcpServers).some(server =>
    !!server && typeof server === 'object' && !!(server as Record<string, unknown>).env);
}
