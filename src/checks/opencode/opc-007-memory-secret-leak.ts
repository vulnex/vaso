import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { scanMemorySecrets } from '../../analyzers/memory-secrets.js';
import { MemoryReader } from '../../analyzers/memory-read.js';

// The global rules file. OpenCode's CLAUDE.md fallback is ~/.claude/CLAUDE.md
// (CC-012 scans it), never one in ~/.config/opencode (session/instruction.ts)
const MEMORY_FILES = ['AGENTS.md'];

async function scanFile(file: string, reader: MemoryReader, evidence: Evidence[]): Promise<void> {
  // Present but unreadable: reported as CONFIG-LOAD
  const content = await reader.read(file);
  if (content === undefined) return;

  for (const e of scanMemorySecrets(file, content)) evidence.push(e);
}

export const opc007 = defineCheck({
  id: 'OPC-007',
  name: 'OpenCode Memory File Secret Leak',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.config/opencode/AGENTS.md for plaintext secrets and high-entropy strings',
  supportedAgents: ['opencode'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    const reader = new MemoryReader(ctx.fs);
    for (const filename of MEMORY_FILES) {
      await scanFile(join(ctx.installation.installDir, filename), reader, evidence);
    }

    return reader.result(h, evidence, {
      passed: `No secrets detected in OpenCode memory files${reader.note()}`,
      failed: (n) => `Found ${n} potential secret(s) in OpenCode memory files`,
      fixDescription: 'Remove the secret from the memory file and rotate the credential — these files are often committed to git',
    });
  },
});
