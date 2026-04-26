import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

const PACKAGE_RUNNERS = new Set(['npx', 'pnpm', 'yarn', 'bunx', 'uvx', 'pipx']);
const PINNED_PACKAGE = /@\d+\.\d+\.\d+/;
const SHA_PINNED = /(?:@sha256:|#[a-f0-9]{7,40})/i;

export const cdx004: CheckModule = {
  id: 'CDX-004',
  name: 'Codex Unpinned MCP Server',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP servers in Codex config launched via package runners without a pinned version',
  supportedAgents: ['codex'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const servers = config.data.mcp_servers as Record<string, unknown> | undefined;
      if (!servers || typeof servers !== 'object') continue;

      for (const [name, server] of Object.entries(servers)) {
        if (!server || typeof server !== 'object') continue;
        const command = (server as Record<string, unknown>).command;
        const args = (server as Record<string, unknown>).args;
        if (typeof command !== 'string') continue;

        const baseCmd = command.split('/').pop() ?? command;
        if (!PACKAGE_RUNNERS.has(baseCmd)) continue;

        const argList = Array.isArray(args)
          ? (args as unknown[]).filter((a): a is string => typeof a === 'string')
          : [];
        const pkgArg = argList.find(a => !a.startsWith('-'));
        if (!pkgArg) continue;

        if (PINNED_PACKAGE.test(pkgArg) || SHA_PINNED.test(pkgArg)) continue;

        evidence.push({
          file: config.filePath,
          snippet: `mcp_servers.${name}: ${command} ${argList.join(' ')}`,
          detail: `Runs "${pkgArg}" via ${baseCmd} with no version pin — supply chain risk`,
        });
      }
    }

    return {
      id: 'CDX-004',
      name: 'Codex Unpinned MCP Server',
      category: 'coding-agent',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'All Codex MCP server packages are version-pinned'
        : `Found ${evidence.length} Codex MCP server(s) running unpinned packages`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Pin packages to a specific version in [mcp_servers.*] config',
    };
  },
};
