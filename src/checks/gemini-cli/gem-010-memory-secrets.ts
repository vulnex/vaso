import { join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { findHighEntropyBlocks } from '../../analyzers/entropy.js';

const KNOWN_KEY_PREFIXES: { pattern: RegExp; name: string }[] = [
  { pattern: /\bsk-or-v1-[A-Za-z0-9]{32,}/, name: 'OpenRouter API key' },
  { pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/, name: 'Anthropic API key' },
  { pattern: /\bsk-[A-Za-z0-9]{32,}/, name: 'OpenAI-style API key' },
  { pattern: /\bAIza[0-9A-Za-z_-]{30,}/, name: 'Google API key' },
  { pattern: /\bghp_[A-Za-z0-9]{20,}/, name: 'GitHub personal access token' },
  { pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/, name: 'Slack token' },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/, name: 'AWS access key ID' },
];

const ENTROPY_THRESHOLD = 5.5;
const MIN_BLOCK_LEN = 40;

const MEMORY_FILES = ['memory.md', 'GEMINI.md'];

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
          detail: `Plaintext ${name} in memory file`,
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

export const gem010 = defineCheck({
  id: 'GEM-010',
  name: 'Gemini Memory File Secret Leak',
  category: 'coding-agent',
  severity: 'info',
  description: 'Scan ~/.gemini/memory.md and GEMINI.md for plaintext secrets and high-entropy strings',
  supportedAgents: ['gemini-cli'],

  async run(ctx, h) {
    const evidence: Evidence[] = [];
    for (const filename of MEMORY_FILES) {
      await scanFile(join(ctx.installation.installDir, filename), ctx, evidence);
    }
    return h.fromEvidence(evidence, {
      passed: 'No secrets detected in Gemini memory files',
      failed: (n) => `Found ${n} potential secret(s) in Gemini memory files`,
      fixDescription: 'Remove the secret from the memory file and rotate the credential — these files often end up in git or shared workspaces',
    });
  },
});
