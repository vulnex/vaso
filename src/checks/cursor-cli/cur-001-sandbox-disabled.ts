import { basename } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const cur001 = defineCheck({
  id: 'CUR-001',
  name: 'Cursor Sandbox Disabled',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Detect when sandbox.mode is "disabled" (cli-config.json) or sandbox.json sets type "insecure_none" — tools run unsandboxed on the host',
  supportedAgents: ['cursor-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      // sandbox.json (user ~/.cursor or per-repo .cursor): type
      // "insecure_none" turns the agent sandbox off (cursor.com/docs/reference/sandbox)
      if (basename(config.filePath) === 'sandbox.json') {
        const type = config.data.type;
        if (typeof type === 'string' && type.toLowerCase() === 'insecure_none') {
          evidence.push({
            file: config.filePath,
            snippet: `type = "${type}"`,
            detail: 'sandbox.json disables the agent sandbox — commands run directly on the host with full filesystem and network access',
          });
        }
        continue;
      }
      const sandbox = config.data.sandbox as Record<string, unknown> | undefined;
      if (!sandbox || typeof sandbox !== 'object') continue;
      const mode = sandbox.mode;
      if (typeof mode === 'string' && mode.toLowerCase() === 'disabled') {
        evidence.push({
          file: config.filePath,
          snippet: `sandbox.mode = "${mode}"`,
          detail: 'All Cursor tool calls execute on the host without sandboxing — relies entirely on permissions.allow as the only gate',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Cursor sandbox is enabled',
      failed: () => 'Cursor sandbox is disabled — tools execute directly on the host',
      fixDescription: 'Set sandbox.mode to "enabled" in ~/.cursor/cli-config.json and sandbox.json type to "workspace_readwrite" (or "workspace_readonly")',
    });
  },
});
