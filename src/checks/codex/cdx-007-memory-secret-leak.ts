import { dirname, join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { memorySecretSeverity, scanMemorySecrets } from '../../analyzers/memory-secrets.js';
import { readTextIfPresent } from '../../adapters/load-if-present.js';

// AGENTS.override.md replaces AGENTS.md at its level when present, so either
// can be the live instructions file (learn.chatgpt.com — AGENTS.md discovery)
const MEMORY_FILES = ['AGENTS.override.md', 'AGENTS.md', 'instructions.md'];

async function scanFile(file: string, ctx: ScanContext, evidence: Evidence[]): Promise<void> {
  // Present but unreadable: reported as CONFIG-LOAD
  const content = await readTextIfPresent(file, ctx.fs);
  if (content === undefined) return;

  evidence.push(...scanMemorySecrets(file, content));
}

export const cdx007 = defineCheck({
  id: 'CDX-007',
  name: 'Codex Memory File Secret Leak',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.codex/AGENTS.md, AGENTS.override.md and instructions.md for plaintext secrets and high-entropy strings',
  supportedAgents: ['codex'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    // A trusted project's instructions live at its root, beside `.codex/`
    const dir = ctx.installation.profile === 'project' ? dirname(ctx.installation.installDir) : ctx.installation.installDir;
    for (const filename of MEMORY_FILES) {
      await scanFile(join(dir, filename), ctx, evidence);
    }

    return h.fromEvidence(evidence, {
      severity: memorySecretSeverity(evidence),
      passed: 'No secrets detected in Codex memory files',
      failed: (n) => `Found ${n} potential secret(s) in Codex memory files`,
      fixDescription: 'Remove the secret from the memory file and rotate the credential — these files are often committed to git',
    });
  },
});
