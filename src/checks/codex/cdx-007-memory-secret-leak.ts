import { dirname, join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { memorySecretSeverity, scanMemorySecrets } from '../../analyzers/memory-secrets.js';
import { MemoryReader } from '../../analyzers/memory-read.js';

// AGENTS.override.md replaces AGENTS.md at its level when present, so either
// can be the live instructions file (learn.chatgpt.com — AGENTS.md discovery)
const MEMORY_FILES = ['AGENTS.override.md', 'AGENTS.md'];
// ~/.codex/instructions.md was read only by the TypeScript CLI (npm
// @openai/codex before 0.20.0); the Rust CLI ignores it
const LEGACY_MEMORY_FILE = 'instructions.md';

function isLegacyTypescriptCli(version: string | undefined): boolean {
  const m = /^(\d+)\.(\d+)\./.exec(version ?? '');
  return !!m && Number(m[1]) === 0 && Number(m[2]) < 20;
}

async function scanFile(file: string, reader: MemoryReader, evidence: Evidence[]): Promise<void> {
  // Present but unreadable: reported as CONFIG-LOAD
  const content = await reader.read(file);
  if (content === undefined) return;

  for (const e of scanMemorySecrets(file, content)) evidence.push(e);
}

export const cdx007 = defineCheck({
  id: 'CDX-007',
  name: 'Codex Memory File Secret Leak',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.codex/AGENTS.md and AGENTS.override.md (and instructions.md for the legacy TypeScript CLI) for plaintext secrets and high-entropy strings',
  supportedAgents: ['codex'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const reader = new MemoryReader(ctx.fs);
    // A trusted project's instructions live at its root, beside `.codex/`
    const dir = ctx.installation.profile === 'project' ? dirname(ctx.installation.installDir) : ctx.installation.installDir;
    const files = ctx.installation.profile !== 'project' && isLegacyTypescriptCli(ctx.installation.version)
      ? [...MEMORY_FILES, LEGACY_MEMORY_FILE]
      : MEMORY_FILES;
    for (const filename of files) {
      await scanFile(join(dir, filename), reader, evidence);
    }

    return h.fromEvidence(evidence, {
      severity: memorySecretSeverity(evidence),
      passed: `No secrets detected in Codex memory files${reader.note()}`,
      failed: (n) => `Found ${n} potential secret(s) in Codex memory files`,
      fixDescription: 'Remove the secret from the memory file and rotate the credential — these files are often committed to git',
    });
  },
});
