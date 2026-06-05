import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { extractPromptNames } from '../../mcp/tool-baseline.js';

/**
 * MCP-026 — Slash-Command / Prompt Overlap.
 *
 * MCP prompts surface as slash commands in clients. When two servers register a
 * prompt/command with the same name, command resolution becomes ambiguous and a
 * malicious server can shadow a trusted command. Hou et al. arXiv 2503.23278
 * §5.2.2 ("slash command overlap"). Lower severity than tool collisions
 * (MCP-025) because prompts are user-invoked rather than model-selected.
 */
export const mcp026 = defineCheck({
  id: 'MCP-026',
  name: 'Slash-Command / Prompt Overlap',
  category: 'mcp',
  severity: 'info',
  description: 'Detect identical prompt/slash-command names registered by different MCP servers',
  supportedAgents: ['mcp'],

  async run(ctx, h) {
    const byName = new Map<string, Set<string>>();

    for (const source of ctx.mcpServerSources ?? []) {
      if (!source.sourceCode) continue;
      for (const prompt of extractPromptNames(source.sourceCode)) {
        if (!byName.has(prompt)) byName.set(prompt, new Set());
        byName.get(prompt)!.add(source.serverName);
      }
    }

    const evidence: Evidence[] = [];
    for (const [prompt, servers] of byName) {
      if (servers.size < 2) continue;
      evidence.push({
        file: [...servers].join(', '),
        snippet: `Prompt/command "${prompt}"`,
        detail: `Slash-command "${prompt}" is registered by ${servers.size} servers (${[...servers].join(', ')}) — command routing is ambiguous and one server can shadow another's command`,
      });
    }

    return h.fromEvidence(evidence, {
      passed: 'No prompt/slash-command name collisions across MCP servers',
      failed: (n) => `Found ${n} prompt/slash-command collision(s) across MCP servers`,
      fixDescription:
        'Namespace prompts per server (e.g. prefix with the server name) so slash-command names cannot collide across servers',
    });
  },
});
