import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { markUntrustedWorkspace } from '../../adapters/folder-trust.js';
import { serverOffPredicate } from '../../mcp/off-lists.js';
import { geminiWorkspaceTrusted } from '../../adapters/gemini.js';
import { broadPrefix, isPolicyFile, policyEvidence } from './policy-rules.js';

/** Shell tool aliases Gemini maps to `run_shell_command` (core `SHELL_TOOL_NAMES`). */
const SHELL_TOOL_NAMES = new Set(['run_shell_command', 'ShellTool']);
/** Legacy `toolName(args)` form, parsed as Gemini's policy config does. */
const TOOL_WITH_ARGS = /^([a-zA-Z0-9_-]+)\((.*)\)$/s;

/**
 * Why a tools.allowed entry auto-approves far more than one command, or
 * undefined. Gemini turns `run_shell_command(<prefix>)` (alias `ShellTool`)
 * into a shell allow rule with that command prefix (policy/config.ts
 * `mapToolsToRules`), so the prefix is judged like a policy-file
 * commandPrefix; a bare shell tool name allows every shell command. An empty
 * `run_shell_command()` adds no allow rule.
 */
function overbroadEntry(entry: string): string | undefined {
  const e = entry.trim();
  if (e === '*') return 'Auto-approves every tool, shell commands included';
  if (SHELL_TOOL_NAMES.has(e)) return 'Auto-approves every shell command';
  const m = TOOL_WITH_ARGS.exec(e);
  if (!m || !SHELL_TOOL_NAMES.has(m[1])) return undefined;
  const args = m[2].trim();
  if (args === '') return undefined;
  if (args === '*') return 'Auto-approves arbitrary shell commands — covers far more than intended';
  const reason = broadPrefix(args);
  return reason ? `Shell commands run without confirmation: the prefix ${reason}` : undefined;
}

export const gem003 = defineCheck({
  id: 'GEM-003',
  name: 'Gemini Overbroad Tools Allow',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect tools.allowed entries and policy-engine allow rules (~/.gemini/policies/*.toml incl. auto-saved.toml, admin policies) that grant unbounded shell or tool access, and MCP servers marked trust:true or allowed whole (no tool-call confirmation)',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const off = await serverOffPredicate(ctx); // switched-off servers never connect

    for (const config of ctx.configs) {
      // Policy engine files (user ~/.gemini/policies, admin system dir)
      if (isPolicyFile(config)) {
        evidence.push(...policyEvidence(config));
        continue;
      }
      // mcpServers.<name>.trust: true "bypasses all tool call confirmations
      // for this server" (Gemini CLI MCP server docs) — an allow-everything
      // rule scoped to one server's tools
      const servers = config.data.mcpServers as Record<string, unknown> | undefined;
      if (servers && typeof servers === 'object') {
        for (const [name, server] of Object.entries(servers)) {
          if (server && typeof server === 'object' && (server as Record<string, unknown>).trust === true
            && !off(name, server, { filePath: config.filePath })) {
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
        const detail = overbroadEntry(entry);
        if (!detail) continue;
        evidence.push({ file: config.filePath, snippet: `tools.allowed: "${entry}"`, detail });
      }
    }

    await markUntrustedWorkspace(ctx, evidence, geminiWorkspaceTrusted);

    return h.fromEvidence(evidence, {
      passed: 'Gemini tools.allowed and policy rules have no overbroad allow entries and no MCP server is trusted',
      failed: (n) => `Found ${n} overbroad allow rule(s) (shell/tool catch-alls or trusted MCP servers) in Gemini config`,
      fixDescription: 'Replace catch-alls with specific commands (e.g. `run_shell_command(git status)`, `run_shell_command(npm test)`) remove broad allow rules from ~/.gemini/policies/*.toml (auto-saved.toml holds "always allow" answers), and drop trust:true from MCP servers',
    });
  },
});
