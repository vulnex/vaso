import { dirname, join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanMemorySecrets } from '../../analyzers/memory-secrets.js';
import { MemoryReader } from '../../analyzers/memory-read.js';
import { isProjectInstall } from './shared.js';

export const msc012 = defineCheck({
  id: 'MSC-012',
  name: 'Muse Code Project Rules Secret Leak',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Scan the project rules Meta Muse Code sends to the model (<workspace>/AGENTS.md, else CLAUDE.md) for plaintext secrets and high-entropy strings',
  supportedAgents: ['muse-code'],

  async run(ctx, h) {
    if (!isProjectInstall(ctx)) return h.passed('Project rules are evaluated on the project installation');
    const workspace = dirname(ctx.installation.installDir);
    const reader = new MemoryReader(ctx.fs);
    const evidence: Evidence[] = [];
    let scanned = 0;
    // Muse reads AGENTS.md and falls back to CLAUDE.md only when it is absent
    for (const name of ['AGENTS.md', 'CLAUDE.md']) {
      const file = join(workspace, name);
      const content = await reader.read(file);
      if (content === undefined) continue;
      scanned++;
      evidence.push(...scanMemorySecrets(file, content, name));
      break;
    }
    if (scanned === 0 && reader.linked.length === 0) return h.passed('No project rules file for this Muse Code workspace');
    return reader.result(h, evidence, {
      severity: 'warning',
      passed: 'No secrets detected in the project rules file',
      failed: (n) => `Found ${n} potential secret(s) in the project rules file`,
      fixDescription: 'Remove the secret from AGENTS.md / CLAUDE.md and rotate it — the file is sent to the model in every session in this workspace',
    });
  },
});
