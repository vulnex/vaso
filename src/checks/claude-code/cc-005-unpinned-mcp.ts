import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { runnerPackage, isPinnedOrLocal, pinProblem } from '../../mcp/package-pin.js';
import { inlineMcpServers, readSubagents } from './subagents.js';

interface ServerSpec {
  command?: string;
  args?: unknown;
}


function checkServer(name: string, server: ServerSpec, file: string, evidence: Evidence[], prefix: string): void {
  const command = server.command;
  if (typeof command !== 'string') return;
  const pkg = runnerPackage(command, server.args);
  if (!pkg || isPinnedOrLocal(pkg)) return;
  const args = Array.isArray(server.args) ? (server.args as unknown[]).filter((a): a is string => typeof a === 'string') : [];

  evidence.push({
    file,
    snippet: `${prefix}${name}: ${command} ${args.join(' ')}`,
    detail: `MCP server package ${pinProblem(pkg)} — supply chain risk`,
  });
}

export const cc005 = defineCheck({
  id: 'CC-005',
  name: 'Unpinned MCP Server Package',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect MCP servers (settings, ~/.claude.json, sub-agent frontmatter) launched via npx/uvx/etc. without a pinned package version',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
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

    // Inline servers in sub-agent frontmatter start with the sub-agent
    // (code.claude.com/docs/en/sub-agents "Scope MCP servers to a subagent")
    for (const agent of await readSubagents(ctx)) {
      for (const [name, srv] of inlineMcpServers(agent.frontmatter)) {
        checkServer(name, srv as ServerSpec, agent.file, evidence, 'mcpServers.');
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'All MCP server packages are version-pinned',
      failed: (n) => `Found ${n} MCP server(s) running unpinned packages`,
      fixDescription: 'Pin packages to a specific version (e.g. @modelcontextprotocol/server-foo@1.2.3)',
    });
  },
});
