import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { findHighEntropyBlocks } from '../../analyzers/entropy.js';

const KNOWN_KEY_PREFIXES: { pattern: RegExp; name: string }[] = [
  { pattern: /\bgho_[A-Za-z0-9]{20,}/, name: 'GitHub OAuth token' },
  { pattern: /\bghp_[A-Za-z0-9]{20,}/, name: 'GitHub PAT' },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}/, name: 'GitHub fine-grained PAT' },
  { pattern: /\bsk-or-v1-[A-Za-z0-9]{32,}/, name: 'OpenRouter API key' },
  { pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/, name: 'Anthropic API key' },
  { pattern: /\bsk-[A-Za-z0-9]{32,}/, name: 'OpenAI-style API key' },
  { pattern: /\bAIza[0-9A-Za-z_-]{30,}/, name: 'Google API key' },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/, name: 'AWS access key ID' },
];

const ENTROPY_THRESHOLD = 5.5;
const MIN_BLOCK_LEN = 40;

async function scanFile(file: string, ctx: ScanContext, evidence: Evidence[]): Promise<void> {
  if (!(await ctx.fs.access(file))) return;
  let content: string;
  try {
    content = await ctx.fs.readFile(file);
  } catch {
    return;
  }

  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    for (const { pattern, name } of KNOWN_KEY_PREFIXES) {
      const m = pattern.exec(lines[i]);
      if (m) {
        evidence.push({
          file,
          line: i + 1,
          snippet: `${m[0].slice(0, 12)}…`,
          detail: `Plaintext ${name} in instructions file`,
        });
      }
    }
  }

  const blocks = findHighEntropyBlocks(content, ENTROPY_THRESHOLD, MIN_BLOCK_LEN);
  for (const b of blocks) {
    if (evidence.some(e => e.file === file && e.line === b.line)) continue;
    evidence.push({
      file,
      line: b.line,
      snippet: b.snippet,
      detail: `High-entropy string (${b.entropy} bits) — possible embedded secret`,
    });
  }
}

export const ghc008 = defineCheck({
  id: 'GHC-008',
  name: 'Copilot CLI Instruction File Secret Leak',
  category: 'coding-agent',
  severity: 'info',
  description: 'Scan ~/.copilot/instructions/*.instructions.md and .github/copilot-instructions.md for plaintext secrets',
  supportedAgents: ['copilot-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];

    // Project-level instructions
    await scanFile(join(process.cwd(), '.github', 'copilot-instructions.md'), ctx, evidence);

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
      passed: 'No secrets detected in Copilot instruction files',
      failed: (n) => `Found ${n} potential secret(s) in Copilot instruction files`,
      fixDescription: 'Remove the secret and rotate the credential — instruction files often end up in git',
    });
  },
});
