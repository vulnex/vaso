import type { CheckModule, ScanContext, CheckResult, Evidence } from '../../core/types.js';

export const cc006: CheckModule = {
  id: 'CC-006',
  name: 'Auto-Trust Project MCP Servers',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect enableAllProjectMcpServers, which trusts MCP servers from any project .mcp.json',
  supportedAgents: ['claude-code'],

  async run(ctx: ScanContext): Promise<CheckResult> {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      if (config.data.enableAllProjectMcpServers === true) {
        evidence.push({
          file: config.filePath,
          detail: 'enableAllProjectMcpServers = true — every project-level .mcp.json is auto-trusted',
        });
      }
    }

    return {
      id: 'CC-006',
      name: 'Auto-Trust Project MCP Servers',
      category: 'coding-agent',
      severity: 'warning',
      passed: evidence.length === 0,
      message: evidence.length === 0
        ? 'Project-level MCP servers require explicit trust'
        : 'enableAllProjectMcpServers is on — any cloned repo can run MCP servers without prompting',
      evidence: evidence.length > 0 ? evidence : undefined,
      fixable: false,
      fixDescription: 'Remove enableAllProjectMcpServers, or use enabledMcpjsonServers for an explicit allowlist',
    };
  },
};
