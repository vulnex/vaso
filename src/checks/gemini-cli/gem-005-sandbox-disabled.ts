import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';

export const gem005 = defineCheck({
  id: 'GEM-005',
  name: 'Gemini Sandbox Disabled',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Detect when tools.sandbox is explicitly disabled in Gemini settings',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    for (const config of ctx.configs) {
      const tools = config.data.tools as Record<string, unknown> | undefined;
      if (!tools || typeof tools !== 'object') continue;
      if (tools.sandbox === false) {
        evidence.push({
          file: config.filePath,
          snippet: 'tools.sandbox = false',
          detail: 'Tools run unsandboxed — shell commands and file ops touch the host directly',
        });
      }
    }

    return h.fromEvidence(evidence, {
      passed: 'Gemini sandbox is not explicitly disabled',
      failed: () => 'Gemini sandbox is disabled — tools execute on the host',
      fixDescription: 'Set tools.sandbox: true (or "docker"/"podman") in ~/.gemini/settings.json',
    });
  },
});
