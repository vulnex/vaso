import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { memorySecretSeverity, scanMemorySecrets } from '../../analyzers/memory-secrets.js';
import { MemoryReader } from '../../analyzers/memory-read.js';
import { recordListFailure } from '../../core/config-loader.js';
import { isExcludedPath } from '../../core/utils.js';

async function scanFile(file: string, reader: MemoryReader, evidence: Evidence[]): Promise<void> {
  // Present but unreadable: reported as CONFIG-LOAD
  const content = await reader.read(file);
  if (content === undefined) return;

  for (const e of scanMemorySecrets(file, content, 'instructions file')) evidence.push(e);
}

const MAX_DEPTH = 8;
const MAX_FILES = 500;

/**
 * `*.instructions.md` files anywhere under `dir` — Copilot CLI reads them
 * from subdirectories too (docs.github.com, "Adding custom instructions for
 * GitHub Copilot CLI": `*.instructions.md` at any depth under
 * `$HOME/.copilot/instructions/` and `.github/instructions/`). Vendor/VCS
 * dirs skipped, depth and count bounded.
 */
async function instructionFiles(ctx: ScanContext, dir: string): Promise<string[]> {
  const out: string[] = [];
  if (!(await ctx.fs.access(dir))) return out;
  const walk = async (d: string, depth: number): Promise<void> => {
    let entries;
    try {
      entries = await ctx.fs.readdirEntries(d);
    } catch (err) {
      // An instructions folder that can't be listed hides its files
      await recordListFailure(d, ctx.fs, err);
      return;
    }
    for (const e of entries) {
      if (out.length >= MAX_FILES) return;
      const p = join(d, e.name);
      if (e.isFile && e.name.endsWith('.instructions.md')) out.push(p);
      else if (e.isDirectory && depth < MAX_DEPTH && !isExcludedPath(dir, p)) await walk(p, depth + 1);
    }
  };
  await walk(dir, 0);
  return out;
}

export const ghc008 = defineCheck({
  id: 'GHC-008',
  name: 'Copilot CLI Instruction File Secret Leak',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan Copilot instruction files (~/.copilot/copilot-instructions.md, .github/copilot-instructions.md, and *.instructions.md at any depth under ~/.copilot/instructions/ and .github/instructions/) for plaintext secrets',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const reader = new MemoryReader(ctx.fs);

    // Project-level instructions, on the project install (installDir = the repo)
    if (ctx.installation.profile === 'project') {
      await scanFile(join(ctx.installation.installDir, '.github', 'copilot-instructions.md'), reader, evidence);
    } else {
      await scanFile(join(ctx.installation.installDir, 'copilot-instructions.md'), reader, evidence);
    }

    // Modular instructions: ~/.copilot/instructions/**/*.instructions.md, and
    // the repository's .github/instructions/**/*.instructions.md
    const instrDir = ctx.installation.profile === 'project'
      ? join(ctx.installation.installDir, '.github', 'instructions')
      : join(ctx.installation.installDir, 'instructions');
    for (const file of await instructionFiles(ctx, instrDir)) await scanFile(file, reader, evidence);

    return h.fromEvidence(evidence, {
      severity: memorySecretSeverity(evidence),
      passed: `No secrets detected in Copilot instruction files${reader.note()}`,
      failed: (n) => `Found ${n} potential secret(s) in Copilot instruction files`,
      fixDescription: 'Remove the secret and rotate the credential — instruction files often end up in git',
    });
  },
});
