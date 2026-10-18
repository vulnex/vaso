import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

// Keys other MCP clients use (Cline/Roo `alwaysAllow`-style, Windsurf
// `autoApprove`). Claude Desktop itself reads none of them: its documented
// server entry is command/args/env (or url/headers), and "Always allow" is
// kept in app state, not in claude_desktop_config.json.
const APPROVAL_KEYS = ['alwaysApprove', 'autoApprove', 'autoApproveTools', 'autoapprove'];

// claude-autoapprove-mcp restarts Claude Desktop with its remote debugging
// port open and injects auto-approval that reads each server's `autoapprove`
// list (github.com/wallneradam/claude_autoapprove_mcp)
const INJECTOR = /claude[-_]autoapprove[-_]mcp/i;
const INJECTOR_KEY = 'autoapprove';

function approvals(obj: Record<string, unknown>): { key: string; tools: string[] } | undefined {
  for (const key of APPROVAL_KEYS) {
    const v = obj[key];
    if (Array.isArray(v)) {
      const tools = v.filter((s): s is string => typeof s === 'string');
      if (tools.length > 0) return { key, tools };
    }
    if (v === true) return { key, tools: ['*'] };
  }
  return undefined;
}

function runsInjector(srv: Record<string, unknown>): boolean {
  const parts = [srv.command, ...(Array.isArray(srv.args) ? srv.args : [])].filter((p): p is string => typeof p === 'string');
  return parts.some(p => INJECTOR.test(p));
}

export const cd006 = defineCheck({
  id: 'CD-006',
  name: 'Always-Approve MCP Tools',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect auto-approve lists that take effect in Claude Desktop (through the claude-autoapprove-mcp injector); other clients\' auto-approve keys, which Claude Desktop ignores, are reported as info',
  supportedAgents: ['claude-desktop'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const mcpServers = config.data.mcpServers as Record<string, unknown> | undefined;
      const servers = mcpServers && typeof mcpServers === 'object'
        ? Object.entries(mcpServers).filter((e): e is [string, Record<string, unknown>] => !!e[1] && typeof e[1] === 'object')
        : [];
      const injector = servers.find(([, srv]) => runsInjector(srv))?.[0];

      const top = approvals(config.data);
      if (top) {
        evidence.push({
          file: config.filePath,
          snippet: `top-level ${top.key} = ${JSON.stringify(top.tools)}`,
          detail: `Claude Desktop does not read a top-level ${top.key} — no tool runs without confirmation because of it`,
          mitigated: true,
        });
      }

      for (const [name, srv] of servers) {
        const found = approvals(srv);
        if (!found) continue;
        const snippet = `mcpServers.${name}.${found.key} = ${JSON.stringify(found.tools)}`;
        if (injector && found.key === INJECTOR_KEY) {
          const broad = found.tools.includes('*') || found.tools.length >= 5;
          evidence.push({
            file: config.filePath,
            snippet,
            detail: `${broad ? 'Broad auto-approve' : `Auto-approves ${found.tools.length} tool(s)`} applied by the "${injector}" server (claude-autoapprove-mcp), which also keeps Claude Desktop's remote debugging port open — prompt-injected calls to these tools run without confirmation`,
          });
        } else {
          evidence.push({
            file: config.filePath,
            snippet,
            detail: injector
              ? `claude-autoapprove-mcp reads "${INJECTOR_KEY}", not "${found.key}" — this list has no effect`
              : `Claude Desktop does not read "${found.key}" (another MCP client's key) — its tools still ask for confirmation`,
            mitigated: true,
          });
        }
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'No auto-approve configuration takes effect for MCP tools',
      failed: (n) => evidence.some(e => !e.mitigated)
        ? `Found ${n} auto-approve configuration(s) — confirmation prompts bypassed`
        : `Found ${n} auto-approve key(s) Claude Desktop ignores`,
      fixDescription: 'Remove auto-approve lists and the claude-autoapprove-mcp server; require explicit confirmation per tool call',
    });
  },
});
