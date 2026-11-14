import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUntrustedProject, settingsConfigs } from './shared.js';

/**
 * Abacus.AI approves MCP tools through permission rules in config.json:
 * `mcp__github` allows every tool of the server, `mcp__github__get_*` a
 * pattern and `mcp__github__create_issue` one tool. Approval lists inside the
 * MCP files (Cline-style `autoApprove`) are ignored by Abacus.AI, so they are
 * not judged here.
 */
const MCP_RULE = /^mcp__(.*)$/;
const ANY = new Set(['', '*', '**']);

/** The server a rule allows wholesale, or undefined for a tool-scoped rule. */
export function blanketMcpServer(rule: string): string | undefined {
  const m = MCP_RULE.exec(rule.trim());
  if (!m) return undefined;
  const rest = m[1];
  const split = rest.indexOf('__');
  const server = split < 0 ? rest : rest.slice(0, split);
  const tool = split < 0 ? '' : rest.slice(split + 2);
  if (!server) return undefined;
  if (/\*/.test(server) || ANY.has(tool)) return server;
  return undefined;
}

export const aba008 = defineCheck({
  id: 'ABA-008',
  name: 'Abacus.AI MCP Server Auto-Approve',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect Abacus.AI permission rules that allow every tool of an MCP server (permissions.allow "mcp__<server>", "mcp__<server>__*" or a wildcard server) — every tool the server exposes, including ones it adds later, runs without a prompt',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of settingsConfigs(ctx.configs)) {
      const permissions = config.data.permissions as Record<string, unknown> | undefined;
      const allow = Array.isArray(permissions?.allow) ? permissions.allow : [];
      for (const entry of allow) {
        if (typeof entry !== 'string') continue;
        const server = blanketMcpServer(entry);
        if (server === undefined) continue;
        evidence.push({
          file: config.filePath,
          snippet: `permissions.allow: "${entry}"`,
          detail: /\*/.test(server)
            ? 'Every tool of every matching MCP server runs without approval — a poisoned or compromised server acts unchecked'
            : `Every tool on MCP server "${server}" runs without approval — a poisoned or compromised server acts unchecked`,
        });
      }
    }

    await markUntrustedProject(ctx, evidence);
    return h.fromEvidence(evidence, {
      passed: 'No Abacus.AI MCP servers are auto-approved wholesale',
      failed: (n) => `Found ${n} Abacus.AI permission rule(s) allowing every tool of an MCP server`,
      fixDescription: 'Replace "mcp__<server>" allow rules with rules for specific read-only tools (e.g. "mcp__github__get_issue")',
    });
  },
});
