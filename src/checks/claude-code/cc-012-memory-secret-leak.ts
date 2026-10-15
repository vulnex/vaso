import { dirname, extname, join } from 'node:path';
import type { Evidence, ScanContext } from '../../core/types.js';
import { defineCheck } from '../../core/check-builder.js';
import { findHighEntropyBlocks } from '../../analyzers/entropy.js';
import { isPlaceholderSecret } from '../../core/patterns.js';

const KNOWN_KEY_PREFIXES: { pattern: RegExp; name: string }[] = [
  { pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}/, name: 'Anthropic API key' },
  { pattern: /\bsk-[A-Za-z0-9]{32,}/, name: 'OpenAI-style API key' },
  { pattern: /\bghp_[A-Za-z0-9]{20,}/, name: 'GitHub personal access token' },
  { pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}/, name: 'GitHub fine-grained PAT' },
  { pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}/, name: 'Slack token' },
  { pattern: /\bAKIA[0-9A-Z]{16}\b/, name: 'AWS access key ID' },
];

async function ruleFiles(dir: string, fs: ScanContext['fs']): Promise<string[]> {
  try {
    const entries = await fs.readdirEntries(dir, { recursive: true });
    return entries
      .filter(e => e.isFile && extname(e.name).toLowerCase() === '.md')
      .map(e => (e.parentPath ? join(e.parentPath, e.name) : join(dir, e.name)));
  } catch {
    return [];
  }
}

const ENTROPY_THRESHOLD = 5.5;
const MIN_BLOCK_LEN = 40;

export const cc012 = defineCheck({
  id: 'CC-012',
  name: 'Memory File Secret Leak',
  category: 'coding-agent',
  severity: 'critical',
  description: 'Scan ~/.claude/CLAUDE.md, rules/*.md and project CLAUDE.md for plaintext secrets and high-entropy strings',
  supportedAgents: ['claude-code'],

  async run(ctx, h) {
    // User install: ~/.claude/CLAUDE.md. Project install (installDir =
    // <repo>/.claude): Claude Code also loads <repo>/CLAUDE.md and the
    // uncommitted <repo>/CLAUDE.local.md. Both scopes load every
    // <installDir>/rules/**/*.md as memory too.
    const memoryFiles = [join(ctx.installation.installDir, 'CLAUDE.md')];
    if (ctx.installation.profile === 'project') {
      const repo = dirname(ctx.installation.installDir);
      memoryFiles.push(join(repo, 'CLAUDE.md'), join(repo, 'CLAUDE.local.md'));
    }
    memoryFiles.push(...await ruleFiles(join(ctx.installation.installDir, 'rules'), ctx.fs));

    const evidence: Evidence[] = [];
    let found = 0;
    for (const memoryFile of memoryFiles) {
      if (!(await ctx.fs.access(memoryFile))) continue;
      let content: string;
      try {
        content = await ctx.fs.readFile(memoryFile);
      } catch {
        continue;
      }
      found++;
      const fileEvidence: Evidence[] = [];
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        for (const { pattern, name } of KNOWN_KEY_PREFIXES) {
          const m = pattern.exec(lines[i]);
          if (m && isPlaceholderSecret(m[0])) continue;
          if (m) {
            fileEvidence.push({
              file: memoryFile,
              line: i + 1,
              snippet: `${m[0].slice(0, 12)}…`,
              detail: `Plaintext ${name} in memory file`,
            });
          }
        }
      }

      const blocks = findHighEntropyBlocks(content, ENTROPY_THRESHOLD, MIN_BLOCK_LEN);
      for (const b of blocks) {
        // De-dup with known-prefix matches on the same line
        if (fileEvidence.some(e => e.line === b.line)) continue;
        fileEvidence.push({
          file: memoryFile,
          line: b.line,
          snippet: b.snippet,
          detail: `High-entropy string (${b.entropy} bits) — possible embedded secret`,
        });
      }
      evidence.push(...fileEvidence);
    }
    if (found === 0) return h.passed('No CLAUDE.md memory file present');

    return h.fromEvidence(evidence, {
      passed: 'No secrets detected in CLAUDE.md memory file',
      failed: (n) => `Found ${n} potential secret(s) in CLAUDE.md`,
      fixDescription: 'Remove the secret from CLAUDE.md and rotate the credential — memory files are often committed to git',
    });
  },
});
