import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

// Patterns under tools.allowed that effectively grant unbounded shell access.
// `run_shell_command` without parens (catch-all for any shell command) and
// the dangerous-shell forms below.
const OVERBROAD_PATTERNS = [
  /^run_shell_command$/,
  /^run_shell_command\s*\(\s*\*\s*\)$/,
  /^run_shell_command\s*\(\s*(bash|sh|zsh|fish|cmd|powershell|pwsh)\s*\)$/i,
  /^run_shell_command\s*\(\s*(rm|sudo|curl|wget|nc|ncat)\s*\)$/i,
  /^\*$/,
];

export const gem003 = defineCheck({
  id: 'GEM-003',
  name: 'Gemini Overbroad Tools Allow',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect tools.allowed entries that grant unbounded shell access, and MCP servers marked trust:true (no tool-call confirmation)',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      // mcpServers.<name>.trust: true "bypasses all tool call confirmations
      // for this server" (Gemini CLI MCP server docs) — an allow-everything
      // rule scoped to one server's tools
      const servers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (servers && typeof servers === 'object') {
        for (const [name, server] of Object.entries(servers)) {
          if (server && typeof server === 'object' && (server as Record<string, unknown>).trust === true) {
            evidence.push({
              file: config.filePath,
              snippet: `mcpServers.${name}.trust = true`,
              detail: 'Every tool this MCP server exposes runs without confirmation — a prompt-injected call reaches it unchecked',
            });
          }
        }
      }

      const tools = config.data.tools as Record<string, unknown> | undefined;
      const allowed = tools?.allowed;
      if (!Array.isArray(allowed)) continue;
      const confirmList = Array.isArray(tools?.confirmationRequired)
        ? new Set((tools.confirmationRequired as unknown[]).filter((s): s is string => typeof s === 'string'))
        : new Set<string>();

      for (const entry of allowed) {
        if (typeof entry !== 'string') continue;
        if (confirmList.has(entry)) continue; // confirmationRequired wins
        if (!OVERBROAD_PATTERNS.some(p => p.test(entry))) continue;
        evidence.push({
          file: config.filePath,
          snippet: `tools.allowed: "${entry}"`,
          detail: 'Auto-approves arbitrary shell commands — covers far more than intended',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Gemini tools.allowed has no overbroad shell entries and no MCP server is trusted',
      failed: (n) => `Found ${n} overbroad allow rule(s) (shell catch-alls or trusted MCP servers) in Gemini config`,
      fixDescription: 'Replace catch-alls with specific commands (e.g. `run_shell_command(git status)`, `run_shell_command(npm test)`) and drop trust:true from MCP servers',
    });
  },
});
