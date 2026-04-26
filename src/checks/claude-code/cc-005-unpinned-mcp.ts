import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

interface ServerSpec {
  command?: string;
  args?: unknown;
}

const PACKAGE_RUNNERS = new Set(['npx', 'pnpm', 'yarn', 'bunx', 'uvx', 'pipx']);
const PINNED_PACKAGE = /@\d+\.\d+\.\d+/;
const SHA_PINNED = /(?:@sha256:|#[a-f0-9]{7,40})/i;

function checkServer(name: string, server: ServerSpec, file: string, evidence: Evidence[], prefix: string): void {
  const command = server.command;
  if (typeof command !== 'string') return;
  const baseCmd = command.split('/').pop() ?? command;
  if (!PACKAGE_RUNNERS.has(baseCmd)) return;

  const args = Array.isArray(server.args) ? (server.args as unknown[]).filter((a): a is string => typeof a === 'string') : [];
  const pkgArg = args.find(a => !a.startsWith('-'));
  if (!pkgArg) return;

  if (PINNED_PACKAGE.test(pkgArg) || SHA_PINNED.test(pkgArg)) return;

  evidence.push({
    file,
    snippet: `${prefix}${name}: ${command} ${args.join(' ')}`,
    detail: `MCP server runs "${pkgArg}" via ${baseCmd} with no version pin — supply chain risk`,
  });
}

export const cc005: CheckModule = {
  id: 'CC-005',
  name: 'Unpinned MCP Server Package',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP servers launched via npx/uvx/etc. without a pinned package version',
  supportedAgents: ['claude-code'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (mcpServers && typeof mcpServers === 'object') {
        for (const [name, srv] of Object.entries(mcpServers)) {
          if (srv && typeof srv === 'object') {
            checkServer(name, srv as ServerSpec, config.filePath, evidence, 'mcpServers.');
          }
        }
      }

      // ~/.claude.json stores per-project MCP under projects[path].mcpServers
      const projects = config.data.projects as Record<string, unknown> | undefined;
      if (projects && typeof projects === 'object') {
        for (const [projectPath, project] of Object.entries(projects)) {
          const projectServers = (project as Record<string, unknown> | undefined)?.mcpServers as Record<string, unknown> | undefined;
          if (projectServers && typeof projectServers === 'object') {
            for (const [name, srv] of Object.entries(projectServers)) {
              if (srv && typeof srv === 'object') {
                checkServer(name, srv as ServerSpec, config.filePath, evidence, `projects[${projectPath}].mcpServers.`);
              }
            }
          }
        }
      }
    }

    return {
      id: 'CC-005',
      name: 'Unpinned MCP Server Package',
      category: 'coding-agent',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'All MCP server packages are version-pinned'
        : `Found ${evidence.length} MCP server(s) running unpinned packages`,
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Pin packages to a specific version (e.g. @modelcontextprotocol/server-foo@1.2.3)',
    };
  },
};
