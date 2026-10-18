import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { memorySecretSeverity, scanMemorySecrets } from '../../analyzers/memory-secrets.js';

const MEMORY_FILES = ['AGENTS.md', 'CLAUDE.md'];

async function scanFile(file: string, ctx: ScanContext, evidence: Evidence[]): Promise<void> {
  if (!(await ctx.fs.access(file))) return;

  let content: string;
  try {
    content = await ctx.fs.readFile(file);
  } catch {
    return;
  }

  evidence.push(...scanMemorySecrets(file, content));
}

export const opc007 = defineCheck({
  id: 'OPC-007',
  name: 'OpenCode Memory File Secret Leak',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.config/opencode/AGENTS.md (and CLAUDE.md fallback) for plaintext secrets and high-entropy strings',
  supportedAgents: ['opencode'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const filename of MEMORY_FILES) {
      await scanFile(join(ctx.installation.installDir, filename), ctx, evidence);
    }

    return h.fromEvidence(evidence, {
      severity: memorySecretSeverity(evidence),
      passed: 'No secrets detected in OpenCode memory files',
      failed: (n) => `Found ${n} potential secret(s) in OpenCode memory files`,
      fixDescription: 'Remove the secret from the memory file and rotate the credential — these files are often committed to git',
    });
  },
});
