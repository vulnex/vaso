import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { memorySecretSeverity, scanMemorySecrets } from '../../analyzers/memory-secrets.js';

async function scanFile(file: string, ctx: ScanContext, evidence: Evidence[]): Promise<void> {
  if (!(await ctx.fs.access(file))) return;
  let content: string;
  try {
    content = await ctx.fs.readFile(file);
  } catch {
    return;
  }

  evidence.push(...scanMemorySecrets(file, content, 'instructions file'));
}

export const ghc008 = defineCheck({
  id: 'GHC-008',
  name: 'Copilot CLI Instruction File Secret Leak',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.copilot/instructions/*.instructions.md and .github/copilot-instructions.md for plaintext secrets',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    // Project-level instructions, on the project install (installDir = the repo)
    if (ctx.installation.profile === 'project') {
      await scanFile(join(ctx.installation.installDir, '.github', 'copilot-instructions.md'), ctx, evidence);
    } else {
      await scanFile(join(ctx.installation.installDir, 'copilot-instructions.md'), ctx, evidence);
    }

    // User-level instructions/*.instructions.md
    const userInstrDir = join(ctx.installation.installDir, 'instructions');
    if (await ctx.fs.access(userInstrDir)) {
      try {
        const entries = await ctx.fs.readdirEntries(userInstrDir);
        for (const e of entries) {
          if (!e.isFile) continue;
          if (!e.name.endsWith('.instructions.md')) continue;
          await scanFile(join(userInstrDir, e.name), ctx, evidence);
        }
      } catch {}
    }

    return h.fromEvidence(evidence, {
      severity: memorySecretSeverity(evidence),
      passed: 'No secrets detected in Copilot instruction files',
      failed: (n) => `Found ${n} potential secret(s) in Copilot instruction files`,
      fixDescription: 'Remove the secret and rotate the credential — instruction files often end up in git',
    });
  },
});
