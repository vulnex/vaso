import { join } from 'node:path';
import type { Evidence } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { findHighEntropyBlocks } from '../../analyzers/entropy.js';

const KNOWN_KEY_PREFIXES: { pattern: RegExp; name: string }[] = [
  { pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/, name: 'Anthropic API key' },
  { pattern: /\bsk-[A-Za-z0-9]{32,}/, name: 'OpenAI-style API key' },
  { pattern: /\bghp_[A-Za-z0-9]{20,}/, name: 'GitHub personal access token' },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}/, name: 'GitHub fine-grained PAT' },
  { pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/, name: 'Slack token' },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/, name: 'AWS access key ID' },
  { pattern: /\bcog_[A-Za-z0-9_-]{16,}/, name: 'Devin API token' },
  { pattern: /\bapk_(?:user_)?[A-Za-z0-9_-]{16,}/, name: 'Devin legacy API token' },
];

const ENTROPY_THRESHOLD = 5.5;
const MIN_BLOCK_LEN = 40;

export const dev007 = defineCheck({
  id: 'DEV-007',
  name: 'Devin Global AGENTS.md Secret Leak',
  category: 'coding-agent',
  severity: 'warning',
  description: 'Scan the global Devin AGENTS.md rules file for plaintext secrets and high-entropy strings',
  supportedAgents: ['devin'],

  async run(ctx, h) {
    const file = join(ctx.installation.installDir, 'AGENTS.md');
    if (!(await ctx.fs.access(file))) {
      return h.passed('Devin AGENTS.md not present');
    }

    let content: string;
    try {
      content = await ctx.fs.readFile(file);
    } catch {
      return h.passed('Devin AGENTS.md not readable — skipping');
    }

    const evidence: Evidence[] = [];
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      for (const { pattern, name } of KNOWN_KEY_PREFIXES) {
        const m = pattern.exec(lines[i]);
        if (m) {
          evidence.push({
            file,
            line: i + 1,
            snippet: `${m[0].slice(0, 12)}…`,
            detail: `Plaintext ${name} in global rules file`,
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

    return h.fromEvidence(evidence, {
      passed: 'No secrets detected in Devin AGENTS.md',
      failed: (n) => `Found ${n} potential secret(s) in Devin AGENTS.md`,
      fixDescription: 'Remove the secret from AGENTS.md and rotate the credential — rules files are injected into every session prompt',
    });
  },
});
