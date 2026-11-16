import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { fixEveryConfig } from '../../remediation/config-writer.js';
import { markUntrustedProject, settingsConfigs } from './shared.js';
import { configFixTargets } from '../../remediation/fix-refusal.js';

export const aba010 = defineCheck({
  id: 'ABA-010',
  name: 'Abacus.AI Loads Other Tools\' MCP Configs',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect loadExternalMcpConfigs: true — Abacus.AI then also launches MCP servers from Cursor, VS Code, Claude Desktop and Windsurf configs, including a cloned repo\'s .cursor/mcp.json and .vscode/mcp.json',
  supportedAgents: ['abacus'],

  fixTargets: configFixTargets,

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const config of settingsConfigs(ctx.configs)) {
      if (config.data.loadExternalMcpConfigs !== true) continue;
      evidence.push({
        file: config.filePath,
        snippet: 'loadExternalMcpConfigs: true',
        detail: 'MCP servers defined for other tools (and in repositories\' .cursor/ and .vscode/ folders) start under Abacus.AI too',
      });
    }
    await markUntrustedProject(ctx, evidence);

    return h.fromEvidence(evidence, {
      passed: 'Abacus.AI loads only its own MCP configs',
      failed: () => 'Abacus.AI also loads MCP servers from other tools\' configs',
      // Untrusted project files are inactive — nothing to fix until trusted
      fixable: evidence.some(e => !e.mitigated),
      fixDescription: 'Set loadExternalMcpConfigs to false and add the servers you need to ~/.abacusai/mcp.json',
    });
  },

  async fix(ctx) {
    return fixEveryConfig(settingsConfigs(ctx.configs).filter(c => c.data.loadExternalMcpConfigs === true), {
      checkId: 'ABA-010',
      path: 'loadExternalMcpConfigs',
      value: false,
      message: 'Set loadExternalMcpConfigs to false',
    });
  },
});
