import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { memorySecretSeverity, scanMemorySecrets } from '../../analyzers/memory-secrets.js';
import { readTextIfPresent } from '../../adapters/load-if-present.js';

const MEMORY_FILES = ['memory.md', 'GEMINI.md'];

async function scanFile(file: string, ctx: ScanContext, evidence: Evidence[]): Promise<void> {
  // Present but unreadable: reported as CONFIG-LOAD
  const content = await readTextIfPresent(file, ctx.fs);
  if (content === undefined) return;

  evidence.push(...scanMemorySecrets(file, content));
}

export const gem010 = defineCheck({
  id: 'GEM-010',
  name: 'Gemini Memory File Secret Leak',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.gemini/memory.md and GEMINI.md for plaintext secrets and high-entropy strings',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const filename of MEMORY_FILES) {
      await scanFile(join(ctx.installation.installDir, filename), ctx, evidence);
    }
    return h.fromEvidence(evidence, {
      severity: memorySecretSeverity(evidence),
      passed: 'No secrets detected in Gemini memory files',
      failed: (n) => `Found ${n} potential secret(s) in Gemini memory files`,
      fixDescription: 'Remove the secret from the memory file and rotate the credential — these files often end up in git or shared workspaces',
    });
  },
});
