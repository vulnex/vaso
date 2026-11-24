import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanMemorySecrets } from '../../analyzers/memory-secrets.js';
import { MemoryReader } from '../../analyzers/memory-read.js';

// QWEN.md is the default context ("memory") file, AGENTS.md the other one
// Qwen loads (memory-constants.ts); `context.fileName` (string or array)
// renames it (Qwen settings.md "Context Files"). Qwen never reads a
// ~/.qwen/memory.md — its auto-memory indexes live in subdirectories.
const MEMORY_FILES = ['QWEN.md', 'AGENTS.md'];

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

async function scanFile(ctx: ScanContext, file: string, reader: MemoryReader, evidence: Evidence[]): Promise<void> {
  // Present but unreadable: reported as CONFIG-LOAD
  const content = await reader.read(file);
  if (content === undefined) {
    // The probe collects ~/.qwen/*.md only (it can't read context.fileName):
    // a renamed context file without .md is never in a snapshot
    if (ctx.fs.kind === 'snapshot' && !/\.md$/i.test(file)) reader.unverified.push(`${file} (not collected: not a .md file)`);
    return;
  }

  // One push per item: a spread of a huge result overflows the call stack
  for (const e of scanMemorySecrets(file, content)) evidence.push(e);
}

export const qc010 = defineCheck({
  id: 'QC-010',
  name: 'Qwen Memory File Secret Leak',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.qwen/QWEN.md (or the configured context.fileName) and AGENTS.md for plaintext secrets and high-entropy strings',
  supportedAgents: ['qwen-code'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const reader = new MemoryReader(ctx.fs);
    for (const filename of contextFileNames(ctx)) {
      await scanFile(ctx, join(ctx.installation.installDir, filename), reader, evidence);
    }
    return reader.result(h, evidence, {
      passed: `No secrets detected in Qwen memory files${reader.note()}`,
      failed: (n) => `Found ${n} potential secret(s) in Qwen memory files`,
      fixDescription: 'Remove the secret from the memory file and rotate the credential — these files often end up in git',
    });
  },
});
