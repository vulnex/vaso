import { dirname, join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { API_KEY_PATTERNS, isPlaceholderSecret } from '../../core/patterns.js';
import { findHighEntropyBlocks } from '../../analyzers/entropy.js';
import { isProjectInstall } from './shared.js';

const ENTROPY_THRESHOLD = 5.5;
const MIN_BLOCK_LEN = 40;

export const aba012 = defineCheck({
  id: 'ABA-012',
  name: 'Abacus.AI AGENTS.md Secret Leak',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Scan the AGENTS.md files Abacus.AI sends on the first turn of every conversation (<workspace>/AGENTS.md, <workspace>/.abacusai/AGENTS.md) for plaintext secrets and high-entropy strings',
  supportedAgents: ['abacus'],

  async run(ctx, h) {
    const installDir = ctx.installation.installDir;
    const files = isProjectInstall(ctx)
      ? [join(dirname(installDir), 'AGENTS.md'), join(installDir, 'AGENTS.md')]
      : [join(installDir, 'AGENTS.md')];

    const evidence: Evidence[] = [];
    let scanned = 0;
    for (const file of files) {
      if (!(await ctx.fs.access(file))) continue;
      let content: string;
      try {
        content = await ctx.fs.readFile(file);
      } catch {
        continue;
      }
      scanned++;
      const lines = content.split('\n');
      lines.forEach((line, i) => {
        for (const { pattern, name } of API_KEY_PATTERNS) {
          const m = pattern.exec(line);
          if (m && isPlaceholderSecret(m[0])) continue;
          if (m) evidence.push({ file, line: i + 1, snippet: `${m[0].slice(0, 12)}…`, detail: `Plaintext ${name} in AGENTS.md` });
        }
      });
      for (const b of findHighEntropyBlocks(content, ENTROPY_THRESHOLD, MIN_BLOCK_LEN)) {
        if (evidence.some(e => e.file === file && e.line === b.line)) continue;
        evidence.push({ file, line: b.line, snippet: b.snippet, detail: `High-entropy string (${b.entropy} bits) — possible embedded secret` });
      }
    }

    if (scanned === 0) return h.passed('No AGENTS.md files for this Abacus.AI installation');
    return h.fromEvidence(evidence, {
      passed: `No secrets detected in ${scanned} AGENTS.md file(s)`,
      failed: (n) => `Found ${n} potential secret(s) in AGENTS.md`,
      fixDescription: 'Remove the secret from AGENTS.md and rotate it — the file is sent to the model with every new conversation (disable with autoLoadAgentsMd: false)',
    });
  },
});
