import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { memorySecretSeverity, scanMemorySecrets } from '../../analyzers/memory-secrets.js';
import { readTextIfPresent } from '../../adapters/load-if-present.js';

// QWEN.md is the default context ("memory") file; `context.fileName` (string
// or array) renames it (Qwen settings.md "Context Files")
const MEMORY_FILES = ['memory.md', 'QWEN.md', 'AGENTS.md'];

function contextFileNames(ctx: ScanContext): string[] {
  const names = new Set(MEMORY_FILES);
  for (const config of ctx.configs) {
    const fileName = (config.data.context as Record<string, unknown> | undefined)?.fileName;
    for (const n of Array.isArray(fileName) ? fileName : [fileName]) {
      // a bare file name only — never follow a configured path out of the dir
      if (typeof n === 'string' && n && !n.includes('/') && !n.includes('\\') && n !== '..') names.add(n);
    }
  }
  return [...names];
}

async function scanFile(file: string, ctx: ScanContext, evidence: Evidence[]): Promise<void> {
  // Present but unreadable: reported as CONFIG-LOAD
  const content = await readTextIfPresent(file, ctx.fs);
  if (content === undefined) return;

  evidence.push(...scanMemorySecrets(file, content));
}

export const qc010 = defineCheck({
  id: 'QC-010',
  name: 'Qwen Memory File Secret Leak',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.qwen/QWEN.md (or the configured context.fileName), memory.md and AGENTS.md for plaintext secrets and high-entropy strings',
  supportedAgents: ['qwen-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const filename of contextFileNames(ctx)) {
      await scanFile(join(ctx.installation.installDir, filename), ctx, evidence);
    }
    return h.fromEvidence(evidence, {
      severity: memorySecretSeverity(evidence),
      passed: 'No secrets detected in Qwen memory files',
      failed: (n) => `Found ${n} potential secret(s) in Qwen memory files`,
      fixDescription: 'Remove the secret from the memory file and rotate the credential — these files often end up in git',
    });
  },
});
