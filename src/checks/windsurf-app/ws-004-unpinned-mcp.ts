import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

const PACKAGE_RUNNERS = new Set(['npx', 'uvx']);

/**
 * A package spec is pinned when it carries an '@version' suffix. An '@' at
 * position 0 is the scope marker (@scope/name), not a pin — so
 * '@scope/name' is unpinned while '@scope/name@1.2.3' and 'name@1.2.3' are pinned.
 */
function isPinned(pkg: string): boolean {
  return pkg.lastIndexOf('@') > 0;
}

/** Local paths and URLs aren't registry packages — version pins don't apply. */
function isLocalOrUrl(pkg: string): boolean {
  return pkg.startsWith('.') || pkg.startsWith('/') || /^[a-z+]+:\/\//i.test(pkg);
}

export const ws004 = defineCheck({
  id: 'WS-004',
  name: 'Windsurf Unpinned MCP Package',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect stdio MCP servers in mcp_config.json launched via npx/uvx/pnpm dlx without a pinned package version',
  supportedAgents: ['windsurf'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const servers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') continue;

      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== 'object') continue;
        const rec = server as Record<string, unknown>;
        const command = rec.command;
        if (typeof command !== 'string') continue;

        const baseCmd = command.split('/').pop() ?? command;
        let argList = Array.isArray(rec.args)
          ? (rec.args as unknown[]).filter((a): a is string => typeof a === 'string')
          : [];

        if (baseCmd === 'pnpm') {
          // Only `pnpm dlx <pkg>` is a package runner.
          const dlxIdx = argList.indexOf('dlx');
          if (dlxIdx === -1) continue;
          argList = argList.slice(dlxIdx + 1);
        } else if (!PACKAGE_RUNNERS.has(baseCmd)) {
          continue;
        }

        // Skip leading flags (-y, --yes, --package=…) to find the package arg.
        const pkgArg = argList.find(a => !a.startsWith('-'));
        if (!pkgArg || isLocalOrUrl(pkgArg)) continue;
        if (isPinned(pkgArg)) continue;

        evidence.push({
          file: config.filePath,
          snippet: `mcpServers.${name}: ${command} ${argList.join(' ')}`,
          detail: `Runs "${pkgArg}" via ${baseCmd} with no version pin — supply chain risk (rug pull / compromised release auto-adopted)`,
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All Windsurf MCP server packages are version-pinned',
      failed: (n) => `Found ${n} Windsurf MCP server(s) running unpinned packages`,
      fixDescription: 'Pin packages to a specific version (e.g. @scope/server@1.2.3) in mcp_config.json',
    });
  },
});
